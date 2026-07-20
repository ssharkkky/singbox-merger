import asyncio
import unittest
from unittest.mock import patch

from fastapi import HTTPException

import main


class FakeRequest:
    def __init__(self, payload, headers=None):
        self.payload = payload
        self.headers = headers or {}
        self.json_called = False

    async def json(self):
        self.json_called = True
        return self.payload


class ResourceLimitTests(unittest.TestCase):
    def test_content_length_is_rejected_before_json_parsing(self):
        request = FakeRequest(
            {"template": "dualstack", "raw": "trojan://x@example.com"},
            {"content-length": str(main.MAX_REQUEST_BODY_BYTES + 1)},
        )

        with self.assertRaises(HTTPException) as captured:
            asyncio.run(main.api_merge(request))

        self.assertEqual(413, captured.exception.status_code)
        self.assertFalse(request.json_called)

    def test_post_rejects_too_many_urls(self):
        request = FakeRequest(
            {
                "template": "dualstack",
                "urls": [
                    f"https://source-{i}.example/sub"
                    for i in range(main.MAX_SUBSCRIPTION_URLS + 1)
                ],
            }
        )

        with self.assertRaises(HTTPException) as captured:
            asyncio.run(main.api_merge(request))

        self.assertEqual(413, captured.exception.status_code)

    def test_post_rejects_oversized_raw_input(self):
        request = FakeRequest(
            {
                "template": "dualstack",
                "raw": "x" * (main.MAX_RAW_BYTES + 1),
            }
        )

        with self.assertRaises(HTTPException) as captured:
            asyncio.run(main.api_merge(request))

        self.assertEqual(413, captured.exception.status_code)

    def test_invalid_profile_and_limit_are_rejected(self):
        for field, value in (("profile", "unknown"), ("limit", 5001)):
            payload = {
                "template": "dualstack",
                "raw": "trojan://x@example.com:443#node",
                field: value,
            }
            with self.subTest(field=field), self.assertRaises(HTTPException) as captured:
                asyncio.run(main.api_merge(FakeRequest(payload)))
            self.assertEqual(400, captured.exception.status_code)

    def test_get_rejects_too_many_urls(self):
        urls = ",".join(
            f"https://source-{i}.example/sub"
            for i in range(main.MAX_SUBSCRIPTION_URLS + 1)
        )

        with self.assertRaises(HTTPException) as captured:
            asyncio.run(
                main.api_merge_get(
                    url=urls,
                    template="dualstack",
                    raw="",
                    expand=True,
                    limit=0,
                    profile="default",
                )
            )

        self.assertEqual(413, captured.exception.status_code)

    def test_raw_node_count_is_bounded(self):
        raw = "\n".join(
            [
                "trojan://one@example.com:443#one",
                "trojan://two@example.com:443#two",
            ]
        )
        with patch.object(main, "MAX_MERGED_NODES", 1):
            with self.assertRaises(HTTPException) as captured:
                main.parse_raw_nodes(raw)

        self.assertEqual(413, captured.exception.status_code)

    def test_subscription_and_raw_nodes_share_one_total_limit(self):
        subscription_node = {
            "type": "trojan",
            "tag": "subscription-node",
            "server": "source.example",
            "server_port": 443,
            "password": "x",
        }

        async def fake_fetch(_urls):
            return main.SubscriptionPayload(nodes=[subscription_node])

        request = FakeRequest(
            {
                "template": "dualstack",
                "urls": ["https://source.example/sub"],
                "raw": "trojan://x@example.com:443#raw-node",
            }
        )
        with patch.object(main, "MAX_MERGED_NODES", 1), patch.object(
            main, "fetch_subscriptions", fake_fetch
        ):
            with self.assertRaises(HTTPException) as captured:
                asyncio.run(main.api_merge(request))

        self.assertEqual(413, captured.exception.status_code)


if __name__ == "__main__":
    unittest.main()
