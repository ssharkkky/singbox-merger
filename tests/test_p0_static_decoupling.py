import asyncio
import json
import unittest
from pathlib import Path
from unittest.mock import patch

import main


class FakeRequest:
    def __init__(self, payload):
        self.payload = payload

    async def json(self):
        return self.payload


class StaticNodeDecouplingTests(unittest.TestCase):
    def test_normal_merge_never_reads_or_injects_local_static_nodes(self):
        public_node = {
            "type": "trojan",
            "tag": "public-node",
            "server": "public.example",
            "server_port": 443,
            "password": "public-password",
        }

        async def fake_fetch(_urls):
            return main.SubscriptionPayload(nodes=[public_node])

        original_read_text = Path.read_text

        def reject_static_file_reads(path, *args, **kwargs):
            if path.name == "static-nodes.json":
                raise AssertionError("local static credential file was read")
            return original_read_text(path, *args, **kwargs)

        with patch.object(Path, "read_text", reject_static_file_reads), patch.object(
            main, "fetch_subscriptions", fake_fetch
        ):
            response = asyncio.run(
                main.api_merge(
                    FakeRequest(
                        {
                            "urls": ["https://public.example/sub"],
                            "template": "dualstack",
                        }
                    )
                )
            )

        config = json.loads(response.body)
        tags = {outbound.get("tag") for outbound in config["outbounds"]}
        self.assertIn("public-node", tags)
        self.assertNotIn("PRIVATE-STATIC-SHOULD-NOT-LEAK", tags)

    def test_normal_get_merge_never_reads_or_injects_local_static_nodes(self):
        public_node = {
            "type": "trojan",
            "tag": "public-get-node",
            "server": "public.example",
            "server_port": 443,
            "password": "public-password",
        }

        async def fake_fetch(_urls):
            return main.SubscriptionPayload(nodes=[public_node])

        original_read_text = Path.read_text

        def reject_static_file_reads(path, *args, **kwargs):
            if path.name == "static-nodes.json":
                raise AssertionError("local static credential file was read")
            return original_read_text(path, *args, **kwargs)

        with patch.object(Path, "read_text", reject_static_file_reads), patch.object(
            main, "fetch_subscriptions", fake_fetch
        ):
            response = asyncio.run(
                main.api_merge_get(
                    url="https://public.example/sub",
                    template="dualstack",
                    raw="",
                    expand=True,
                    limit=0,
                    profile="ios",
                )
            )

        config = json.loads(response.body)
        tags = {outbound.get("tag") for outbound in config["outbounds"]}
        endpoint_tags = {
            endpoint.get("tag") for endpoint in config.get("endpoints", [])
        }
        self.assertIn("public-get-node", tags)
        self.assertNotIn("PRIVATE-STATIC-SHOULD-NOT-LEAK", tags)
        self.assertNotIn("PRIVATE-HOME-SHOULD-NOT-LEAK", endpoint_tags)

    def test_ios_transform_never_reads_local_static_endpoints(self):
        template = main.load_template("dualstack")
        config = main.inject_into_template(
            template,
            [
                {
                    "type": "trojan",
                    "tag": "public-node",
                    "server": "public.example",
                    "server_port": 443,
                    "password": "public-password",
                }
            ],
        )

        original_read_text = Path.read_text

        def reject_static_file_reads(path, *args, **kwargs):
            if path.name == "static-nodes.json":
                raise AssertionError("local static credential file was read")
            return original_read_text(path, *args, **kwargs)

        with patch.object(Path, "read_text", reject_static_file_reads):
            ios_config = main.transform_for_ios(config)

        endpoint_tags = {
            endpoint.get("tag") for endpoint in ios_config.get("endpoints", [])
        }
        self.assertNotIn("PRIVATE-HOME-SHOULD-NOT-LEAK", endpoint_tags)

    def test_private_bundle_preserves_nodes_shells_and_ios_endpoints(self):
        bundle = {
            "format": "singbox-merger-private-v1",
            "nodes": [
                {
                    "type": "shadowsocks",
                    "tag": "private-node",
                    "method": "2022-blake3-aes-128-gcm",
                    "password": "private-password",
                    "detour": "private-shell",
                }
            ],
            "shells": [
                {
                    "type": "shadowtls",
                    "tag": "private-shell",
                    "server": "private.example",
                    "server_port": 443,
                    "version": 3,
                    "password": "private-shell-password",
                }
            ],
            "profile_endpoints": {
                "ios": [
                    {
                        "type": "wireguard",
                        "tag": "private-home",
                        "address": ["10.99.0.2/32"],
                        "private_key": "private-wireguard-key",
                        "peers": [],
                    }
                ]
            },
        }

        payload = main.parse_subscription_payload(json.dumps(bundle))

        self.assertEqual(["private-node"], [n["tag"] for n in payload.nodes])
        self.assertEqual(
            ["private-shell"], [s["tag"] for s in payload.extra_outbounds]
        )
        self.assertEqual(
            ["private-home"],
            [e["tag"] for e in payload.profile_endpoints["ios"]],
        )

    def test_explicit_private_bundle_is_merged_for_ios(self):
        payload = main.SubscriptionPayload(
            nodes=[
                {
                    "type": "shadowsocks",
                    "tag": "private-node",
                    "method": "2022-blake3-aes-128-gcm",
                    "password": "private-password",
                    "detour": "private-shell",
                }
            ],
            extra_outbounds=[
                {
                    "type": "shadowtls",
                    "tag": "private-shell",
                    "server": "private.example",
                    "server_port": 443,
                    "version": 3,
                    "password": "private-shell-password",
                }
            ],
            profile_endpoints={
                "ios": [
                    {
                        "type": "wireguard",
                        "tag": "private-home",
                        "address": ["10.99.0.2/32"],
                        "private_key": "private-wireguard-key",
                        "peers": [],
                    }
                ]
            },
        )

        async def fake_fetch(_urls):
            return payload

        with patch.object(main, "fetch_subscriptions", fake_fetch):
            response = asyncio.run(
                main.api_merge(
                    FakeRequest(
                        {
                            "urls": ["https://private.example/secret.json"],
                            "template": "dualstack",
                            "profile": "ios",
                        }
                    )
                )
            )

        config = json.loads(response.body)
        outbound_tags = {outbound.get("tag") for outbound in config["outbounds"]}
        endpoint_tags = {
            endpoint.get("tag") for endpoint in config.get("endpoints", [])
        }
        self.assertIn("private-node", outbound_tags)
        self.assertIn("private-shell", outbound_tags)
        self.assertIn("private-home", endpoint_tags)
        home_rules = [
            rule for rule in config["route"]["rules"]
            if rule.get("outbound") == "private-home"
        ]
        self.assertEqual(1, len(home_rules))
        self.assertEqual(
            ["192.168.0.0/24", "192.168.2.0/24", "10.99.0.0/24"],
            home_rules[0]["ip_cidr"],
        )

    def test_fetch_logs_never_include_subscription_path_or_query(self):
        async def fake_fetch_text(_url, _timeout):
            return "trojan://password@public.example:443#public-node"

        secret_url = (
            "https://private.example/private-nodes/SECRET-PATH.json"
            "?token=SECRET-QUERY"
        )
        with patch.object(
            main, "_fetch_subscription_text", fake_fetch_text
        ), self.assertLogs("merger", level="INFO") as captured:
            payload = asyncio.run(main.fetch_one_sub(secret_url))

        logs = "\n".join(captured.output)
        self.assertEqual(["public-node"], [n["tag"] for n in payload.nodes])
        self.assertIn("private.example", logs)
        self.assertNotIn("SECRET-PATH", logs)
        self.assertNotIn("SECRET-QUERY", logs)

    def test_server_disables_uvicorn_access_log(self):
        with patch.object(main.uvicorn, "run") as run:
            main.run_server()

        run.assert_called_once_with(
            main.app,
            host="127.0.0.1",
            port=25600,
            log_level=main.LOG_LEVEL,
            access_log=False,
        )

    def test_imported_app_disables_uvicorn_access_logger(self):
        self.assertTrue(main.logging.getLogger("uvicorn.access").disabled)

    def test_http_client_loggers_cannot_record_subscription_urls(self):
        self.assertGreaterEqual(
            main.logging.getLogger("httpx").getEffectiveLevel(), main.logging.WARNING
        )
        self.assertGreaterEqual(
            main.logging.getLogger("httpcore").getEffectiveLevel(),
            main.logging.WARNING,
        )


if __name__ == "__main__":
    unittest.main()
