import asyncio
import socket
import unittest
from unittest.mock import patch

import httpx
from fastapi import HTTPException

import main


PUBLIC_V4 = "93.184.216.34"


def public_dns(*_args, **_kwargs):
    return [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            (PUBLIC_V4, 443),
        )
    ]


class SsrfProtectionTests(unittest.TestCase):
    def test_ipv4_mapped_loopback_is_blocked(self):
        with self.assertRaises(HTTPException) as captured:
            asyncio.run(
                main.validate_url("http://[::ffff:127.0.0.1]:8080/private")
            )

        self.assertEqual(400, captured.exception.status_code)

    def test_non_http_scheme_is_blocked(self):
        with self.assertRaises(HTTPException) as captured:
            asyncio.run(main.validate_url("file:///etc/passwd"))

        self.assertEqual(400, captured.exception.status_code)

    def test_any_non_public_dns_answer_blocks_the_host(self):
        answers = public_dns() + [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("127.0.0.1", 443),
            )
        ]
        with patch.object(main.socket, "getaddrinfo", return_value=answers):
            with self.assertRaises(HTTPException) as captured:
                asyncio.run(main.validate_url("https://mixed.example/sub"))

        self.assertEqual(400, captured.exception.status_code)

    def test_validated_dns_address_is_pinned_for_the_request(self):
        calls = []

        async def fake_send(_client, url, host, port, address):
            calls.append((url, host, port, address))
            return httpx.Response(
                200,
                content=b"trojan://pw@example.com:443#Pinned",
                request=httpx.Request("GET", url),
            )

        with patch.object(main.socket, "getaddrinfo", side_effect=public_dns), patch.object(
            main, "_send_pinned_request", fake_send
        ):
            raw = asyncio.run(
                main._fetch_subscription_text("https://public.example/sub")
            )

        self.assertIn("#Pinned", raw)
        self.assertEqual(
            [("https://public.example/sub", "public.example", 443, PUBLIC_V4)],
            calls,
        )

    def test_pinned_https_request_keeps_original_host_and_sni(self):
        class FakeClient:
            request = None

            def build_request(self, method, url, headers):
                return httpx.Request(method, url, headers=headers)

            async def send(self, request, stream):
                self.request = request
                self.stream = stream
                return httpx.Response(200, content=b"ok", request=request)

        client = FakeClient()
        response = asyncio.run(
            main._send_pinned_request(
                client,
                "https://public.example/sub",
                "public.example",
                443,
                PUBLIC_V4,
            )
        )

        self.assertEqual(PUBLIC_V4, client.request.url.host)
        self.assertEqual("public.example", client.request.headers["host"])
        self.assertEqual(
            "public.example", client.request.extensions["sni_hostname"]
        )
        self.assertTrue(client.stream)
        asyncio.run(response.aclose())

    def test_redirect_target_is_validated_before_second_request(self):
        calls = []

        async def fake_send(_client, url, host, port, address):
            calls.append((url, host, port, address))
            return httpx.Response(
                302,
                headers={"Location": "https://127.0.0.1:8443/private"},
                request=httpx.Request("GET", url),
            )

        with patch.object(main.socket, "getaddrinfo", side_effect=public_dns), patch.object(
            main, "_send_pinned_request", fake_send
        ):
            with self.assertRaises(HTTPException) as captured:
                asyncio.run(
                    main._fetch_subscription_text("https://public.example/start")
                )

        self.assertEqual(400, captured.exception.status_code)
        self.assertEqual(1, len(calls))

    def test_https_redirect_cannot_downgrade_to_http(self):
        async def fake_send(_client, url, _host, _port, _address):
            return httpx.Response(
                302,
                headers={"Location": "http://other.example/sub"},
                request=httpx.Request("GET", url),
            )

        with patch.object(main.socket, "getaddrinfo", side_effect=public_dns), patch.object(
            main, "_send_pinned_request", fake_send
        ):
            with self.assertRaises(HTTPException) as captured:
                asyncio.run(
                    main._fetch_subscription_text("https://public.example/start")
                )

        self.assertEqual(400, captured.exception.status_code)
        self.assertEqual("HTTPS downgrade redirect blocked", captured.exception.detail)


if __name__ == "__main__":
    unittest.main()
