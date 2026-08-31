# singbox-merger

`singbox-merger` 是一个 FastAPI 服务，用于拉取显式提供的 sing-box 订阅、解析节点并注入 JSON 模板。它提供 Web UI、`GET/POST /api/merge` 和 `/api/templates`。

内置模板：

- `dualstack`：UDP 请求路由到当前选择的出站，适用于确认所选节点支持 UDP 的订阅，也是默认模板。
- `tcp-only`：UDP 请求明确拒绝，适用于包含不支持 UDP 节点的订阅。

两个模板都包含一条按 Unix 用户 `nativeudp` 匹配的 `DIRECT` 路由，供本机 Native Naive 客户端建立外层连接时避开透明代理回环；其他系统或未使用该用户的客户端不会命中此规则。两者的区别仅是普通应用 UDP 是否放行。

模板名称通过 `template` 参数选择，`/api/templates` 会返回可用模板及其说明。

## 安全边界

- 订阅地址只允许 HTTP(S) 且所有解析结果必须是公网地址。
- DNS 结果固定到实际连接，重定向逐跳复核，HTTPS 不允许降级。
- 单个上游响应最多 5 MiB，最多 5 次重定向。
- 单次 merge 最多 8 个 URL、1 MiB raw 输入和 5000 个节点。
- 不读取本机 `static-nodes.json`；私有节点只能来自本次请求显式指定的订阅。
- 公网部署仍应在 Nginx 设置请求体、速率和连接数上限。

## 本地运行

需要 Python 3.12：

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --no-deps -r requirements.lock
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python main.py
```

服务默认只监听 `127.0.0.1:25600`。不要直接把 Uvicorn 暴露到公网。

## API 示例

```bash
curl -sS http://127.0.0.1:25600/api/templates

curl -sS -H 'Content-Type: application/json' \
  --data '{"raw":"trojan://example","template":"dualstack"}' \
  http://127.0.0.1:25600/api/merge

# TCP-only variant
curl -sS -G \
  --data-urlencode 'template=tcp-only' \
  --data-urlencode 'url=https://example.com/sub' \
  http://127.0.0.1:25600/api/merge
```

订阅 URL 和节点内容属于凭据，不应进入 access log、命令历史或 CI 输出。

## 生产发布

生产使用 `deploy/deploy-release.sh <git-ref>` 创建只读、按 commit SHA 命名的 release：

1. 从 GitHub 获取指定 ref。
2. 建立独立 `.venv` 并安装 `requirements.lock`。
3. 执行全部单元测试。
4. 原子切换 `/opt/singbox-merger-deploy/current`。
5. 只重启 `singbox-merger.service` 并做 loopback 健康检查；失败时恢复上一 symlink。

首次部署前安装 `deploy/singbox-merger.service` 和发布脚本。旧 release 不自动删除，便于人工回滚。
首次准备 release 时可设置 `MERGER_SKIP_RESTART=1`，安装 unit 并完成预检后再单独重启服务。
