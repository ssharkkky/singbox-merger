#!/usr/bin/env python3
"""
Sing-Box Subscription Merger
多订阅链接 / 纯文本节点 → 注入模板 → 输出完整配置

POST /api/merge  {"urls": [...], "raw": "trojan://...", "template": "dualstack"}
GET  /api/merge?url=...&raw=...&template=dualstack
GET  /api/templates
GET  /           Web UI
"""

import base64
import ipaddress
import json
import logging
import re
import socket
import asyncio
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote
from typing import Optional

import httpx
from fastapi import FastAPI, Query, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
import uvicorn

# ── Config ──────────────────────────────────────────────────────────
TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_NODES_PATH = Path(__file__).parent / "static-nodes.json"
LOG_LEVEL = "info"
FETCH_PROXY: Optional[str] = None
FETCH_TIMEOUT = 30

# ── 节点分组匹配规则 ────────────────────────────────────────────────
# key = 模板 outbound tag（空 outbounds 数组的槽位）
# match_all    → 所有节点都加入
# match        → 标签包含任一关键字
# exclude      → 标签包含任一关键字则排除

INJECT_RULES: dict[str, dict] = {
    "♻️ 自动选择": {"match_all": True},
    "♻️ 新加坡自动": {"match": ["Singapore", "SG", "新加坡", "🇸🇬"]},
    "♻️ 日本自动": {"match": ["Japan", "Tokyo", "JP", "日本", "🇯🇵"]},
    "♻️ 美国自动": {"match": ["US", "USA", "United States", "美国", "🇺🇸", "wago", "BWH", "合租",
                  "Los Angeles", "San Jose", "New York", "Seattle",
                  "Silicon", "San Francisco", "Dallas", "Chicago"]},
}

logging.basicConfig(level=getattr(logging, LOG_LEVEL.upper(), logging.INFO))
log = logging.getLogger("merger")

app = FastAPI(title="Sing-Box Merger")


# ══════════════════════════════════════════════════════════════════════
# 工具函数
# ══════════════════════════════════════════════════════════════════════

def decode_base64(s: str) -> str:
    s = s.strip()
    try:
        b = s.encode() if isinstance(s, str) else s
        missing = len(b) % 4
        if missing:
            b += b"=" * (4 - missing)
        return base64.b64decode(b).decode("utf-8", errors="replace")
    except Exception:
        return ""


NODE_PREFIXES = ("vmess://", "vless://", "trojan://", "ss://", "hysteria2://", "hy2://")


def split_lines(text: str) -> list[str]:
    """尝试 base64 解码；如果解码结果不含有效节点 URI，则用原文"""
    decoded = decode_base64(text)
    if decoded and any(prefix in decoded for prefix in NODE_PREFIXES):
        return decoded.splitlines()
    return text.splitlines()


# ══════════════════════════════════════════════════════════════════════
# 节点解析
# ══════════════════════════════════════════════════════════════════════

# --- vmess ---
def _parse_vmess(uri: str) -> Optional[dict]:
    try:
        raw = uri[len("vmess://"):]
        data = json.loads(decode_base64(raw))
        tag = data.get("ps", data.get("remark", "vmess"))
        out = {
            "type": "vmess",
            "tag": tag,
            "server": data["add"],
            "server_port": int(data.get("port", 443)),
            "uuid": data["id"],
            "security": data.get("scy", "auto"),
            "alter_id": int(data.get("aid", 0)),
        }
        net = data.get("net", "tcp")
        if net == "ws":
            out["transport"] = {"type": "ws", "path": data.get("path", "/")}
            if data.get("host"):
                out["transport"]["headers"] = {"Host": data["host"]}
        elif net == "grpc":
            out["transport"] = {"type": "grpc", "service_name": data.get("path", "").lstrip("/")}
        elif net == "h2":
            out["transport"] = {"type": "http", "host": [data.get("host", "")], "path": data.get("path", "/")}
        if data.get("tls") == "tls":
            out["tls"] = {
                "enabled": True,
                "server_name": data.get("sni", data.get("host", "")),
                "insecure": data.get("allowInsecure", "false") == "true",
            }
        return out
    except Exception as e:
        log.debug(f"vmess parse: {e}")
        return None


# --- vless ---
def _parse_vless(uri: str) -> Optional[dict]:
    try:
        u = urlparse(uri)
        params = parse_qs(u.query, keep_blank_values=True)
        tag = unquote(u.fragment) or "vless"
        def p(k, d=None):
            v = params.get(k, [d])[0]; return v if v is not None else d

        out = {"type": "vless", "tag": tag, "server": u.hostname,
               "server_port": u.port or 443, "uuid": u.username}
        flow = p("flow", "")
        if flow:
            out["flow"] = flow

        net = p("type", "tcp")
        if net == "ws":
            out["transport"] = {"type": "ws", "path": p("path", "/")}
            if p("host"):
                out["transport"]["headers"] = {"Host": p("host")}
        elif net == "grpc":
            out["transport"] = {"type": "grpc", "service_name": p("serviceName", "")}
        elif net == "h2":
            out["transport"] = {"type": "http", "host": [p("host", "")], "path": p("path", "/")}

        sec = p("security", "none")
        if sec in ("tls", "reality"):
            sni = p("sni", u.hostname)
            tls = {"enabled": True, "server_name": sni or "", "insecure": p("allowInsecure", "0") == "1"}
            if sec == "reality":
                tls["utls"] = {"enabled": True, "fingerprint": p("fp", "chrome")}
                tls["reality"] = {"enabled": True, "public_key": p("pbk", ""), "short_id": p("sid", "")}
            out["tls"] = tls
            ech_val = p("ech")
            if ech_val:
                out["tls"]["ech"] = {"enabled": True, "query_server_name": ech_val.split("+", 1)[0]}
        return out
    except Exception as e:
        log.debug(f"vless parse: {e}")
        return None


# --- trojan ---
def _parse_trojan(uri: str) -> Optional[dict]:
    try:
        u = urlparse(uri)
        params = parse_qs(u.query, keep_blank_values=True)
        tag = unquote(u.fragment) or "trojan"
        def p(k, d=None):
            v = params.get(k, [d])[0]; return v if v is not None else d

        out = {"type": "trojan", "tag": tag, "server": u.hostname,
               "server_port": u.port or 443, "password": unquote(u.username or "")}
        net = p("type", "tcp")
        if net == "ws":
            out["transport"] = {"type": "ws", "path": p("path", "/")}
            if p("host"):
                out["transport"]["headers"] = {"Host": p("host")}
        elif net == "grpc":
            out["transport"] = {"type": "grpc", "service_name": p("serviceName", "")}
        if p("security", "tls") == "tls":
            out["tls"] = {"enabled": True, "server_name": p("sni", u.hostname) or "",
                          "insecure": p("allowInsecure", "0") == "1"}
            ech_val = p("ech")
            if ech_val:
                out["tls"]["ech"] = {"enabled": True, "query_server_name": ech_val.split("+", 1)[0]}
        return out
    except Exception as e:
        log.debug(f"trojan parse: {e}")
        return None


# --- shadowsocks ---
def _parse_ss(uri: str) -> Optional[dict]:
    try:
        u = urlparse(uri)
        tag = unquote(u.fragment) or "ss"
        userinfo = decode_base64(u.username or "") or unquote(u.username or "")
        if ":" not in userinfo:
            return None
        method, password = userinfo.split(":", 1)
        return {"type": "shadowsocks", "tag": tag, "server": u.hostname,
                "server_port": u.port or 8388, "method": method, "password": password}
    except Exception as e:
        log.debug(f"ss parse: {e}")
        return None


# --- hysteria2 ---
def _parse_hy2(uri: str) -> Optional[dict]:
    try:
        u = urlparse(uri)
        params = parse_qs(u.query, keep_blank_values=True)
        tag = unquote(u.fragment) or "hy2"
        def p(k, d=None):
            v = params.get(k, [d])[0]; return v if v is not None else d

        out = {"type": "hysteria2", "tag": tag, "server": u.hostname,
               "server_port": u.port or 443, "password": unquote(u.username or ""),
               "tls": {"enabled": True, "server_name": p("sni", u.hostname) or "",
                       "insecure": p("insecure", p("allowInsecure", "0")) == "1"}}
        if p("obfs"):
            out["obfs"] = {"type": p("obfs"), "password": p("obfs-password", "")}
        return out
    except Exception as e:
        log.debug(f"hy2 parse: {e}")
        return None


PARSERS = [
    ("vmess://", _parse_vmess),
    ("vless://", _parse_vless),
    ("trojan://", _parse_trojan),
    ("ss://", _parse_ss),
    ("hysteria2://", _parse_hy2),
    ("hy2://", _parse_hy2),
]


def parse_node(line: str) -> Optional[dict]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    for prefix, parser in PARSERS:
        if line.startswith(prefix):
            return parser(line)
    log.debug(f"Unknown: {line[:60]}")
    return None


def parse_raw_nodes(text: str) -> list[dict]:
    """从纯文本中解析节点（每行一个 URI）"""
    nodes = []
    for line in split_lines(text):
        node = parse_node(line)
        if node:
            nodes.append(node)
    log.info(f"Parsed {len(nodes)} nodes from raw text")
    return nodes


PRIVATE_NETS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


async def validate_url(url: str):
    """检查 URL 是否指向内网地址（防 SSRF）"""
    u = urlparse(url)
    host = u.hostname
    if not host:
        raise HTTPException(400, f"Invalid URL: {url[:60]}")
    try:
        ip = ipaddress.ip_address(host)
        for net in PRIVATE_NETS:
            if ip in net:
                raise HTTPException(400, f"Private IP blocked: {host}")
        return
    except ValueError:
        pass  # 域名，需解析 DNS
    loop = asyncio.get_running_loop()
    try:
        addrs = await loop.run_in_executor(None, socket.getaddrinfo, host, 0)
    except socket.gaierror:
        raise HTTPException(400, f"Cannot resolve: {host}")
    for addr in addrs:
        ip = ipaddress.ip_address(addr[4][0])
        for net in PRIVATE_NETS:
            if ip in net:
                raise HTTPException(400, f"Private IP blocked: {host} -> {ip}")


async def fetch_one_sub(url: str, timeout: int = FETCH_TIMEOUT) -> list[dict]:
    """拉取单个订阅链接"""
    await validate_url(url)
    log.info(f"Fetching: {url[:80]}...")
    async with httpx.AsyncClient(
        proxy=FETCH_PROXY, timeout=timeout, follow_redirects=True,
    ) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        raw = resp.text

    # 如果是 sing-box JSON，提取其中的 outbounds
    if raw.strip().startswith("{"):
        try:
            cfg = json.loads(raw)
            obs = cfg.get("outbounds", [])
            nodes = [o for o in obs if o.get("type") not in ("selector", "urltest", "direct", "block", "dns")]
            if nodes:
                log.info(f"Extracted {len(nodes)} outbounds from sing-box JSON")
                return nodes
        except json.JSONDecodeError:
            pass

    # 标准 base64 / 纯文本 节点列表
    nodes = []
    for line in split_lines(raw):
        if line.startswith("proxies:") or line.startswith("Proxy:"):
            continue
        node = parse_node(line)
        if node:
            nodes.append(node)
    log.info(f"Parsed {len(nodes)} nodes from {url[:60]}")
    return nodes


async def fetch_subscriptions(urls: list[str]) -> list[dict]:
    """并行拉取多个订阅链接，合并去重"""
    if not urls:
        return []
    tasks = [fetch_one_sub(u) for u in urls]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    seen: set[str] = set()
    merged: list[dict] = []
    for i, res in enumerate(results):
        if isinstance(res, Exception):
            if isinstance(res, HTTPException):
                raise res  # SSRF 等安全异常直接抛出，不吞
            log.warning(f"Subscription [{i}] failed: {res}")
            continue
        for node in res:
            tag = node.get("tag", "")
            if tag and tag not in seen:
                seen.add(tag)
                merged.append(node)
    log.info(f"Merged {len(merged)} unique nodes from {len(urls)} subscriptions")
    return merged


# ══════════════════════════════════════════════════════════════════════
# 模板管理
# ══════════════════════════════════════════════════════════════════════

def list_templates() -> list[dict]:
    result = []
    if not TEMPLATES_DIR.exists():
        return result
    for f in sorted(TEMPLATES_DIR.glob("*.json")):
        try:
            data = json.loads(f.read_text())
            desc = data.get("_meta", {}).get("description", f.stem)
        except Exception:
            desc = f.stem
        result.append({"name": f.stem, "description": desc})
    return result


def load_template(name: str) -> dict:
    # 只允许字母数字连字符下划线，防路径穿越
    if not re.fullmatch(r"[a-zA-Z0-9_-]+", name):
        raise HTTPException(400, "Invalid template name")
    path = TEMPLATES_DIR / f"{name}.json"
    if not path.exists():
        raise HTTPException(404, f"Template '{name}' not found")
    return json.loads(path.read_text())


# ══════════════════════════════════════════════════════════════════════
# 节点注入
# ══════════════════════════════════════════════════════════════════════

def categorize_nodes(nodes: list[dict]) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = {}
    for node in nodes:
        tag = node.get("tag", "")
        if not tag:
            continue
        for group_tag, rule in INJECT_RULES.items():
            groups.setdefault(group_tag, [])
            if rule.get("match_all"):
                groups[group_tag].append(tag)
                continue
            exclude = rule.get("exclude", [])
            if any(kw.lower() in tag.lower() for kw in exclude):
                continue
            match = rule.get("match", [])
            if not match or any(kw.lower() in tag.lower() for kw in match):
                groups[group_tag].append(tag)
    return groups


def load_static_nodes() -> tuple[list[dict], list[dict]]:
    """加载固定节点(自有基础设施, 原生 sing-box outbound)。
    static-nodes.json 是一个 entry 列表, 每个 entry:
      {"node": {...主 outbound, 参与正常分组...},
       "shells": [{...附属 outbound, 仅追加不分组, 如 shadowtls 外壳...}]}
    返回 (nodes, shells)。文件含凭据, 已在 .gitignore, 不提交。"""
    try:
        entries = json.loads(STATIC_NODES_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return [], []
    except Exception as e:
        log.warning(f"static-nodes load failed: {e}")
        return [], []
    nodes, shells = [], []
    for e in entries:
        n = e.get("node")
        if isinstance(n, dict) and n.get("tag"):
            nodes.append(n)
        for s in e.get("shells", []):
            if isinstance(s, dict) and s.get("tag"):
                shells.append(s)
    return nodes, shells


def merge_static_nodes(all_nodes: list[dict]) -> tuple[list[dict], list[dict]]:
    """把固定节点并入节点列表(固定节点优先, 去除订阅里同 tag 的副本), 返回 (合并后节点, shells)。"""
    static_nodes, shells = load_static_nodes()
    if not static_nodes and not shells:
        return all_nodes, []
    static_tags = {n["tag"] for n in static_nodes}
    merged = [n for n in all_nodes if n.get("tag") not in static_tags]
    merged.extend(static_nodes)
    if static_nodes:
        log.info(f"Static nodes injected: {sorted(static_tags)}; shells: {[s.get('tag') for s in shells]}")
    return merged, shells


def inject_into_template(template: dict, nodes: list[dict], expand: bool = True,
                         extra_outbounds: Optional[list[dict]] = None) -> dict:
    import copy
    config = copy.deepcopy(template)
    config.pop("_meta", None)
    outbounds = config.get("outbounds", [])

    groups = categorize_nodes(nodes)

    # 注入到空槽位
    for ob in outbounds:
        tag = ob.get("tag", "")
        out_list = ob.get("outbounds", None)
        if out_list is not None and isinstance(out_list, list) and len(out_list) == 0:
            if tag in groups:
                node_tags = groups[tag]
                ob["outbounds"] = node_tags
                log.info(f"Injected {len(node_tags)} → '{tag}'")

    # 展开 selector：引用 urltest 子组的，追加子组节点到选择器列表
    # 仅 expand=True 时展开（iOS 内存限制需关闭）
    if expand:
        for ob in outbounds:
            if ob.get("type") != "selector":
                continue
            sel_out = ob.get("outbounds", [])
            for ref_tag in list(sel_out):
                sub = next((o for o in outbounds if o.get("tag") == ref_tag and o.get("type") == "urltest"), None)
                if sub:
                    for node_tag in sub.get("outbounds", []):
                        if node_tag not in sel_out:
                            sel_out.append(node_tag)

    # 未分配节点补入 ♻️ 自动选择
    for ob in outbounds:
        if ob.get("tag") == "♻️ 自动选择":
            existing = set(ob.get("outbounds", []))
            all_tags = [n["tag"] for n in nodes if n.get("tag")]
            missing = [t for t in all_tags if t not in existing]
            if missing:
                ob["outbounds"] = list(existing) + missing
                log.info(f"Added {len(missing)} ungrouped → ♻️ 自动选择")
            break

    # 追加节点 outbound 条目（去重）
    existing_tags = {o.get("tag") for o in outbounds if o.get("tag")}
    new_obs = [n for n in nodes if n.get("tag") and n["tag"] not in existing_tags]
    # 附属 outbound(如 shadowtls 外壳): 仅追加, 不参与任何分组
    for s in (extra_outbounds or []):
        if s.get("tag") and s["tag"] not in existing_tags:
            new_obs.append(s)
            existing_tags.add(s["tag"])
    insert_idx = len(outbounds)
    for i, ob in enumerate(outbounds):
        if ob.get("type") in ("direct", "block") and not ob.get("tag", "").startswith("♻️"):
            insert_idx = i
            break
    outbounds[insert_idx:insert_idx] = new_obs
    log.info(f"Appended {len(new_obs)} node entries")

    # 清理空组（循环直到稳定，因为删一个可能让引用它的父组也变空）
    while True:
        empty_tags = {o["tag"] for o in outbounds
                      if o.get("type") in ("urltest", "selector")
                      and isinstance(o.get("outbounds"), list)
                      and len(o.get("outbounds", [])) == 0}
        if not empty_tags:
            break
        outbounds[:] = [o for o in outbounds if o.get("tag") not in empty_tags]
        for o in outbounds:
            if isinstance(o.get("outbounds"), list):
                o["outbounds"] = [t for t in o["outbounds"] if t not in empty_tags]
        log.info(f"Removed empty groups: {empty_tags}")

    return config


# ══════════════════════════════════════════════════════════════════════

def transform_for_ios(config: dict) -> dict:
    """从 dualstack 裁剪出 iOS 精简版"""
    import copy
    c = copy.deepcopy(config)

    # 1. 删服务专属 selector + 区域组 + IPv4/IPv6 分组
    remove_tags = {
        "🤖 AI / ChatGPT", "📹 YouTube", "🎬 Netflix", "📱 Telegram",
        "🍎 Apple", "🪟 Microsoft", "🎮 游戏",
        "🇸🇬 新加坡", "🇯🇵 日本", "🇺🇸 美国",
        "♻️ 新加坡自动", "♻️ 日本自动", "♻️ 美国自动",
        "🌐 IPv4 节点", "🌐 IPv6 节点", "♻️ IPv4 自动", "♻️ IPv6 自动",
    }


    c["outbounds"] = [o for o in c["outbounds"] if o.get("tag") not in remove_tags]
    for o in c["outbounds"]:
        if isinstance(o.get("outbounds"), list):
            o["outbounds"] = [t for t in o["outbounds"] if t not in remove_tags]

    # Fix dangling defaults: if a selector default was removed, point to auto-select
    for ob in c["outbounds"]:
        if isinstance(ob.get("default"), str) and ob["default"] in remove_tags:
            ob["default"] = "♻️ 自动选择"
    # iOS: inject all nodes from urltest into selector so user can manually pick
    _auto = next((o for o in c["outbounds"] if o.get("tag") == "♻️ 自动选择"), None)
    if _auto:
        _node_tags = [t for t in (_auto.get("outbounds") or []) if isinstance(t, str)]
        for ob in c["outbounds"]:
            if ob.get("tag") == "🚀 节点选择" and ob.get("type") == "selector":
                existing = set(ob.get("outbounds", []))
                for nt in _node_tags:
                    if nt not in existing:
                        ob["outbounds"].append(nt)
                break

    # iOS: 精简版删了 🇺🇸 美国等 region outbounds，修复 route.final 悬空引用
    if c["route"].get("final") in remove_tags:
        c["route"]["final"] = "🚀 节点选择"

    # 2. 路由规则只保留核心 rule_set
    keep_rule_sets = {"geosite-cn", "geosite-geolocation-!cn", "geoip-cn",
                       "geosite-category-ads-all", "game-download"}
    c["route"]["rule_set"] = [rs for rs in c["route"]["rule_set"]
                               if rs["tag"] in keep_rule_sets]

    new_rules = []
    for r in c["route"]["rules"]:
        rs = r.get("rule_set", [])
        out = r.get("outbound", "")
        act = r.get("action", "")
        if act in ("sniff", "hijack-dns"):
            new_rules.append(r)
        elif r.get("protocol") == "ntp":
            new_rules.append(r)
        elif r.get("ip_is_private"):
            new_rules.append(r)
        elif r.get("ip_version") == 6:
            new_rules.append(r)
        elif rs and all(s in keep_rule_sets for s in rs):
            new_rules.append(r)
        elif act == "reject" and rs:
            new_rules.append(r)
    c["route"]["rules"] = new_rules

    # 回家(仅 iOS): 从 static-nodes.json 注入 WireGuard endpoint + 分流规则(主模板保持纯净,不含 WG)
    try:
        _entries = json.loads(STATIC_NODES_PATH.read_text(encoding="utf-8"))
    except Exception:
        _entries = []
    _home_eps = [e["endpoint"] for e in _entries
                 if isinstance(e.get("endpoint"), dict) and e["endpoint"].get("tag")]
    if _home_eps:
        eps = c.setdefault("endpoints", [])
        _exist = {x.get("tag") for x in eps}
        for ep in _home_eps:
            if ep["tag"] not in _exist:
                eps.append(copy.deepcopy(ep)); _exist.add(ep["tag"])
        _pos = next((i for i, r in enumerate(c["route"]["rules"]) if r.get("ip_is_private")),
                    len(c["route"]["rules"]))
        c["route"]["rules"].insert(_pos, {
            "ip_cidr": ["192.168.0.0/24", "10.99.0.0/24"],
            "outbound": _home_eps[0]["tag"], "action": "route"})

    # 3. 删 mixed-in inbound
    c["inbounds"] = [i for i in c["inbounds"] if i.get("tag") != "mixed-in"]

    # 4. TUN 精简
    for i in c["inbounds"]:
        if i.get("type") == "tun":
            i["stack"] = "system"
            i["strict_route"] = False
            i["mtu"] = 1500
            # 回家: 移除含家庭网段的 route_exclude(否则 192.168.0.0/24 / 10.99.0.0/24 被挡在隧道外)
            if isinstance(i.get("route_exclude_address"), list):
                i["route_exclude_address"] = [a for a in i["route_exclude_address"]
                                              if a not in ("192.168.0.0/16", "10.0.0.0/8")]

    # 5. 删 NTP, cache_file, http_clients, experimental（精简版不需要）
    c.pop("ntp", None)
    exp = c.get("experimental", {})
    exp.pop("cache_file", None)
    exp.pop("clash_api", None)           # iOS 无 dashboard 需求，移除避免闪退
    if not exp:
        c.pop("experimental", None)

    # 6. DNS 去掉 dns_local
    c["dns"]["servers"] = [s for s in c["dns"]["servers"] if s.get("tag") != "dns_local"]
    c["dns"]["rules"] = [r for r in c["dns"]["rules"] if r.get("server") != "dns_local"]

    # 7. iOS 沙箱无 /tmp 写权限，移除日志文件输出
    c["log"].pop("output", None)

    return c


def transform_for_router(config: dict) -> dict:
    """路由器模式：TUN 加 auto_redirect + strict_route=false"""
    import copy
    c = copy.deepcopy(config)


    # 0. lllinya.com DNS:
    #    内网服务子域名 → 本地 dnsmasq(address= → webserver)；apex/www/其它 → dns_direct 公网解析。
    #    旧设计把整个 *.lllinya.com 丢给 dnsmasq 让它自行裁决,但 dnsmasq 对未命中名字(apex/www)
    #    转发上游 53,经 sing-box auto_redirect 的 DNS 劫持 DNAT 回 dns-locallllinya 形成死循环,
    #    打满 dnsmasq 150 并发槽导致全网 DNS 间歇故障。故在 sing-box 侧就按名字分流,不再依赖 dnsmasq 转发。
    #    新增内网服务子域名时,需同步 OpenWrt /etc/config/dhcp 的 address= 与下面这份列表。
    _LLLINYA_LOCAL = [
        "vault.lllinya.com", "ha.lllinya.com", "pve.lllinya.com", "nas.lllinya.com",
        "agent.lllinya.com", "auth.lllinya.com", "memos.lllinya.com", "qb.lllinya.com",
    ]
    c["dns"]["servers"].insert(0, {"type": "udp", "tag": "dns-locallllinya", "server": "127.0.0.1"})
    # 先插 suffix→dns_direct(兜底:apex/www/未知)
    c["dns"]["rules"].insert(0, {"domain_suffix": ["lllinya.com"], "server": "dns_direct"})
    # 再插精确子域名→dnsmasq,插在最前,优先于上面的 suffix 兜底
    c["dns"]["rules"].insert(0, {"domain": _LLLINYA_LOCAL, "server": "dns-locallllinya"})
    # 0.1 *.lllinya.com 全量路由直连 — 避开 geosite-!cn 代理
    #    sniff 之后插入，确保域名已嗅探
    _pos = next((i for i, r in enumerate(c["route"]["rules"]) if r.get("action") == "sniff"), 0) + 1
    c["route"]["rules"].insert(_pos, {"domain_suffix": ["lllinya.com"], "outbound": "DIRECT"})
    
    # 1. TUN inbound 加 auto_redirect + strict_route=false（绕过 PPPoE 路由冲突）
    for inb in c.get("inbounds", []):
        if inb.get("type") == "tun":
            inb["auto_redirect"] = True
            inb["strict_route"] = False

    # 2. 路由器不需要 mixed-in（SOCKS/HTTP），避免端口 2080 冲突

    # 3. 路由器写日志到文件（macOS/iOS 沙盒无 /tmp 写权限，由模板默认不带 output，仅 router 开启）
    c["log"]["output"] = "/tmp/sing-box.log"

    # 6. Dashboard / clash_api — 监听所有接口 + yacd UI
    exp = c.setdefault("experimental", {})
    ca = exp.setdefault("clash_api", {})
    ca["external_controller"] = "0.0.0.0:9090"
    ca["external_ui"] = "/etc/sing-box/dashboard"
    ca["external_ui_download_url"] = "https://github.com/haishanh/yacd/archive/gh-pages.tar.gz"

    return c


# ══════════════════════════════════════════════════════════════════════
# API
# ══════════════════════════════════════════════════════════════════════

@app.get("/api/templates")
async def api_templates():
    return list_templates()


@app.post("/api/merge")
async def api_merge(request: Request):
    """POST /api/merge
    Body: {"urls": ["url1",...], "raw": "trojan://...", "template": "dualstack"}
    至少需要一个 url 或 raw
    """
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON body")

    template_name = data.get("template", "").strip()
    expand = data.get("expand", True)
    limit = data.get("limit", 0)
    profile = data.get("profile", "default")  # "ios" 触发裁剪
    if not template_name:
        raise HTTPException(400, "Missing 'template'")

    urls = data.get("urls", [])
    if isinstance(urls, str):
        urls = [urls]
    raw = data.get("raw", "").strip()

    # 兼容单 url 字段
    single = data.get("url", "").strip()
    if single:
        urls.append(single)

    if not urls and not raw:
        raise HTTPException(400, "Need at least one subscription URL or raw nodes")

    # 收集所有节点
    all_nodes: list[dict] = []

    if urls:
        try:
            sub_nodes = await fetch_subscriptions(urls)
            all_nodes.extend(sub_nodes)
        except Exception as e:
            raise HTTPException(502, f"Subscription fetch error: {e}")

    if raw:
        raw_nodes = parse_raw_nodes(raw)
        # 去重
        seen = {n.get("tag") for n in all_nodes if n.get("tag")}
        for n in raw_nodes:
            if n.get("tag") not in seen:
                all_nodes.append(n)
                seen.add(n.get("tag"))

    if limit > 0 and len(all_nodes) > limit:
        all_nodes = all_nodes[:limit]
        log.info(f"Trimmed to {limit} nodes")

    # 固定节点(自有基础设施)注入
    all_nodes, static_shells = merge_static_nodes(all_nodes)

    if not all_nodes:
        raise HTTPException(422, "No valid nodes found")

    template = load_template(template_name)
    config = inject_into_template(template, all_nodes, expand, extra_outbounds=static_shells)

    if profile == "ios":
        config = transform_for_ios(config)
        log.info("Applied iOS profile transform")
    elif profile == "router":
        config = transform_for_router(config)
        log.info("Applied router profile transform")

    return JSONResponse(content=config, headers={
        "Content-Disposition": f"attachment; filename=singbox-{template_name}.json"
    })


@app.get("/api/merge")
async def api_merge_get(
    url: str = Query("", description="Comma-separated subscription URLs"),
    template: str = Query(..., description="Template name"),
    raw: str = Query("", description="Raw node text"),
    expand: bool = Query(True, description="Expand selectors"),
    limit: int = Query(0, description="Max nodes (0=all)"),
    profile: str = Query("default", description="Profile (ios)"),
):
    """GET /api/merge?url=...&template=dualstack&profile=ios"""
    all_nodes: list[dict] = []

    if url:
        urls_list = [u.strip() for u in url.split(",") if u.strip()]
        if urls_list:
            try:
                all_nodes = await fetch_subscriptions(urls_list)
            except Exception as e:
                raise HTTPException(502, f"Fetch error: {e}")

    if raw:
        raw_nodes = parse_raw_nodes(raw)
        seen = {n.get("tag") for n in all_nodes if n.get("tag")}
        for n in raw_nodes:
            if n.get("tag") not in seen:
                all_nodes.append(n)

    if limit > 0 and len(all_nodes) > limit:
        all_nodes = all_nodes[:limit]
        log.info(f"Trimmed to {limit} nodes")

    # 固定节点(自有基础设施)注入
    all_nodes, static_shells = merge_static_nodes(all_nodes)

    if not all_nodes:
        raise HTTPException(422, "No valid nodes found")

    tmpl = load_template(template)
    config = inject_into_template(tmpl, all_nodes, expand, extra_outbounds=static_shells)

    if profile == "ios":
        config = transform_for_ios(config)
        log.info("Applied iOS profile transform")
    elif profile == "router":
        config = transform_for_router(config)
        log.info("Applied router profile transform")

    return PlainTextResponse(
        json.dumps(config, ensure_ascii=False, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=singbox-{template}.json"}
    )


# ══════════════════════════════════════════════════════════════════════
# Web UI
# ══════════════════════════════════════════════════════════════════════

INDEX_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sing-Box Merger</title>
<style>
:root { color-scheme: dark; }
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font: 14px/1.6 system-ui, sans-serif; background: #0d1117; color: #c9d1d9;
       max-width: 900px; margin: 0 auto; padding: 2rem 1rem; }
h1 { font-size: 1.5rem; margin-bottom: 1.5rem; color: #58a6ff; }
h2 { font-size: .95rem; color: #8b949e; margin: 1rem 0 .3rem; border-top: 1px solid #21262d; padding-top: .8rem; }
label { display: block; margin: .8rem 0 .3rem; font-size: .85rem; color: #8b949e; }
input, select, textarea { width: 100%; padding: .6rem .8rem; border: 1px solid #30363d;
    border-radius: 6px; background: #161b22; color: #c9d1d9; font-size: .9rem;
    font-family: monospace; outline: none; transition: border-color .2s; }
input:focus, select:focus, textarea:focus { border-color: #58a6ff; }
textarea { min-height: 120px; resize: vertical; }
#output { min-height: 350px; }
.url-row { display: flex; gap: .4rem; align-items: center; }
.url-row input { flex: 1; }
.btn-sm { padding: .4rem .8rem; font-size: .8rem; border: 1px solid #30363d; border-radius: 6px;
    background: #21262d; color: #c9d1d9; cursor: pointer; white-space: nowrap; }
.btn-sm:hover { background: #30363d; }
.btn-row { display: flex; gap: .6rem; margin: 1rem 0; }
button { padding: .6rem 1.5rem; border: none; border-radius: 6px; cursor: pointer;
    font-size: .9rem; font-weight: 500; transition: background .2s; }
.btn-go { background: #238636; color: #fff; }
.btn-go:hover { background: #2ea043; }
.btn-copy { background: #30363d; color: #c9d1d9; }
.btn-copy:hover { background: #484f58; }
.status { font-size: .8rem; color: #8b949e; min-height: 1.5em; }
.status.err { color: #f85149; }
.status.ok { color: #3fb950; }
details { margin: .3rem 0; }
summary { cursor: pointer; color: #58a6ff; font-size: .85rem; }
</style>
</head>
<body>

<h1>Sing-Box Config Merger</h1>

<h2>订阅链接（每行一个）</h2>
<textarea id="urls-ta" rows="4" placeholder="https://example1.com/sub?token=xxx&#10;https://example2.com/sub?token=yyy"></textarea>

<h2>或直接粘贴节点</h2>
<textarea id="raw" placeholder="trojan://password@server:443?sni=...#Node1&#10;vless://uuid@server:443?...&#10;vmess://..."></textarea>

<label for="tpl">配置模板</label>
<select id="tpl"><option>加载中...</option></select>

<div class="btn-row">
  <button class="btn-go" onclick="generate()">生成配置</button>
  <button class="btn-copy" onclick="copyOutput()">复制</button>
  <label style="display:flex;align-items:center;gap:.4rem;font-size:.8rem;color:#8b949e;cursor:pointer;margin-left:1rem">
    <input type="checkbox" id="ios-mode" style="width:auto" onchange="toggleIos()">
    iOS 精简模式（内存受限设备）
  </label>
  <label style="display:flex;align-items:center;gap:.4rem;font-size:.8rem;color:#8b949e;cursor:pointer;margin-left:1rem">
    <input type="checkbox" id="router-mode" style="width:auto" onchange="toggleRouter()">
    路由器模式（OpenWrt 网关）
  </label>
</div>

<div class="status" id="status"></div>

<div id="sub-box" style="margin-bottom:.8rem;">
  <label for="sub-url">🔗 订阅链接（粘贴到 sing-box 客户端）</label>
  <div class="url-row">
    <input id="sub-url" readonly style="flex:1" placeholder="请生成配置后点击此处复制"
           onclick="copySubUrl()">
    <button class="btn-sm" onclick="copySubUrl()">复制</button>
  </div>
</div>

<label for="output">输出</label>
<textarea id="output" readonly placeholder="点击「生成配置」开始..."></textarea>

<script>
async function loadTemplates() {
  try {
    const res = await fetch('/api/templates');
    const data = await res.json();
    const sel = document.getElementById('tpl');
    sel.innerHTML = '';
    data.forEach(t => {
      const o = document.createElement('option');
      o.value = t.name;
      o.textContent = t.description || t.name;
      sel.appendChild(o);
    });
  } catch(e) { document.getElementById('tpl').innerHTML = '<option>Failed</option>'; }
}

function getUrls() {
  return document.getElementById('urls-ta').value.split(String.fromCharCode(10))
    .map(s => s.trim()).filter(Boolean);
}

async function generate() {
  const urls = getUrls();
  const raw = document.getElementById('raw').value.trim();
  const tpl = document.getElementById('tpl').value;
  const status = document.getElementById('status');
  const output = document.getElementById('output');

  if (!urls.length && !raw) {
    status.className='status err'; status.textContent='请填写订阅链接或粘贴节点';
    return;
  }

  status.className = 'status'; status.textContent = 'Pulling subscriptions...';
  output.value = '';

  try {
    const ios = document.getElementById('ios-mode').checked;
    const router = document.getElementById('router-mode').checked;
    const body = {template: tpl, expand: true};
    if (ios) { body.profile = 'ios'; body.expand = false; }
    else if (router) { body.profile = 'router'; }
    if (urls.length) body.urls = urls;
    if (raw) body.raw = raw;

    const res = await fetch('/api/merge', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body)
    });
    const data = await res.json();
    if (!res.ok) {
      status.className = 'status err';
      status.textContent = data.detail || res.statusText;
      return;
    }
    output.value = JSON.stringify(data, null, 2);
    status.className = 'status ok';
    status.textContent = 'Done! ' + data.outbounds?.length + ' outbounds';

    // 生成订阅链接
    const subUrl = location.origin + '/api/merge?' +
      'url=' + encodeURIComponent(urls.join(',')) +
      '&template=' + encodeURIComponent(tpl) +
      (ios ? '&expand=false&profile=ios' : '') +
      (router ? '&profile=router' : '') +
      (raw ? '&raw=' + encodeURIComponent(raw) : '');
    document.getElementById('sub-url').value = subUrl;
  } catch(e) {
    status.className = 'status err';
    status.textContent = e.message;
  }
}

function copyOutput() {
  const ta = document.getElementById('output');
  ta.select();
  document.execCommand('copy');
  document.getElementById('status').textContent = 'Copied to clipboard';
}

function copySubUrl() {
  const el = document.getElementById('sub-url');
  if (!el.value) { document.getElementById('status').textContent = '请先生成配置'; return; }
  el.select();
  navigator.clipboard.writeText(el.value);
  document.getElementById('status').textContent = '📋 订阅链接已复制';
  setTimeout(() => { document.getElementById('status').textContent = ''; }, 2000);
}

function toggleIos() {
  const el = document.getElementById('sub-url');
  if (!el.value) return;
  const ios = document.getElementById('ios-mode').checked;
  if (ios && !el.value.includes('profile=ios')) {
    el.value = el.value.replace('&expand=false', '&expand=false&profile=ios').replace('&&', '&');
    if (!el.value.includes('expand=false')) el.value += '&expand=false&profile=ios';
  } else if (!ios) {
    el.value = el.value.replace('&expand=false&profile=ios', '').replace('&expand=false', '');
  }
}

function toggleRouter() {
  const el = document.getElementById('sub-url');
  if (!el.value) return;
  const router = document.getElementById('router-mode').checked;
  if (router && !el.value.includes('profile=router')) {
    el.value += (el.value.includes('?') ? '&' : '?') + 'profile=router';
  } else if (!router) {
    el.value = el.value.replace('&profile=router', '').replace('profile=router&', '');
  }
}

loadTemplates();
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def index():
    return INDEX_HTML


# ══════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=25600, log_level=LOG_LEVEL)
