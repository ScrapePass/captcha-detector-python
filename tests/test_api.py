"""Python API: response objects of common HTTP clients, result shape, options, custom signatures, CLI."""

import asyncio
import io
import json
import re
import subprocess
import sys
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import captcha_detector as cd
from captcha_detector.__main__ import main as cli_main

RECAPTCHA = '<html><head><title>Sign up</title><script src="https://www.google.com/recaptcha/api.js"></script></head><body><form><div class="g-recaptcha" data-sitekey="x"></div></form></body></html>'
DATADOME = '<html><head><title>example.com</title></head><body><script>var dd={"cid":"AHrlqAAAAAMA","hsh":"A55FBF4311ED6F1BF9911EB71931D5","t":"fe","host":"geo.captcha-delivery.com"}</script><script src="https://ct.captcha-delivery.com/c.js"></script></body></html>'
CLEAN = "<html><head><title>Shoes</title></head><body><h1>Running shoes</h1><p>" + "Great shoes. " * 50 + "</p></body></html>"
CF_CHALLENGE = '<html><head><title>Just a moment...</title></head><body><div id="challenge-form"></div><script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1"></script></body></html>'
AKAMAI_BLOCK = "<html><head><title>Access Denied</title></head><body>You don't have permission to access this resource. Reference #18.2f1a</body></html>"


class FakeRequests:
    """Shaped like requests.Response."""

    def __init__(self, text, status_code=200, headers=None, url="https://api.example/v1", cookies=None):
        self.text = text
        self.content = text.encode()
        self.status_code = status_code
        self.headers = headers or {}
        self.url = url
        self.cookies = cookies or []


class FakeScrapy:
    """Shaped like scrapy.http.HtmlResponse: bytes header names and list values."""

    def __init__(self, text, status=200):
        self.text = text
        self.status = status
        self.headers = {b"Server": [b"cloudflare"], b"Cf-Mitigated": [b"challenge"]}
        self.url = "https://shop.example/"


class FakeUrllib:
    """Shaped like urllib.request's response: read() and getcode()."""

    def __init__(self, body):
        self._b = body.encode()
        self.headers = {"Content-Type": "text/html"}

    def read(self):
        return self._b

    def getcode(self):
        return 200

    def geturl(self):
        return "https://shop.example/x"


class Cookie:
    def __init__(self, name):
        self.name = name


class Api(unittest.TestCase):
    def test_result_shape(self):
        r = cd.detect_html(RECAPTCHA, url="https://shop.example/")
        self.assertEqual(list(r.keys()), ["captcha", "visible", "challenge_page", "blocked", "detections", "summary", "url", "mode", "version"])
        self.assertTrue(r.captcha)
        self.assertIsNone(r.visible)
        self.assertEqual(r.mode, "html")
        d = r.detections[0]
        self.assertEqual((d.id, d.kind, d.subtype, d.confidence), ("recaptcha", "widget", "v2-checkbox", 0.99))
        self.assertEqual(list(d.keys()), ["id", "name", "vendor", "kind", "subtype", "confidence", "visible", "evidence", "site"])
        json.dumps(r)  # plain JSON
        with self.assertRaises(AttributeError):
            r.nope

    def test_requests_like(self):
        res = FakeRequests(RECAPTCHA)
        r = cd.detect_response(res, url="https://shop.example/signup")
        self.assertEqual(r.detections[0].id, "recaptcha")
        self.assertEqual(r.url, "https://shop.example/signup")
        # without url: the response's own url
        self.assertEqual(cd.detect_response(res).url, "https://api.example/v1")

    def test_scraper_json(self):
        body = json.dumps({"success": True, "result": {"status_code": 403, "url": "https://shop.example/p/1", "content": DATADOME}})
        r = cd.detect_response(FakeRequests(body, headers={"content-type": "application/json"}))
        self.assertTrue(r.challenge_page, r.summary)
        self.assertEqual(r.url, "https://shop.example/p/1")
        # parsed JSON, bytes, strings, lists
        self.assertTrue(cd.detect_response({"html": RECAPTCHA}).captcha)
        self.assertTrue(cd.detect_response(RECAPTCHA.encode()).captcha)
        self.assertTrue(cd.detect_response(json.dumps({"body": RECAPTCHA})).captcha)
        self.assertTrue(cd.detect_response([{"url": "https://a.example", "html": RECAPTCHA}]).captcha)

    def test_target_status_inside_json_wins(self):
        body = {"data": {"statusCode": "403", "headers": {"server": "AkamaiGHost"}, "html": AKAMAI_BLOCK}}
        r = cd.detect_response(FakeRequests(json.dumps(body), status_code=200))
        self.assertTrue(r.blocked, r.summary)

    def test_scrapy_like_bytes_headers(self):
        r = cd.detect_response(FakeScrapy("<html><head><title>x</title></head><body>hi</body></html>", status=403))
        self.assertTrue(r.challenge_page, r.summary)
        self.assertIn("cf-mitigated: challenge", [e["value"] for d in r.detections for e in d.evidence])

    def test_urllib_like(self):
        r = cd.detect_response(FakeUrllib(CF_CHALLENGE))
        self.assertTrue(r.challenge_page)
        self.assertEqual(r.url, "https://shop.example/x")

    def test_clean_and_empty(self):
        for x in (CLEAN, "", None, b"", {"items": [1, 2, 3], "next": None}, [], "{not json", "<<<>>>"):
            self.assertFalse(cd.detect_response(x).captcha, repr(x)[:40])

    def test_options_override(self):
        r = cd.detect_response(FakeRequests(AKAMAI_BLOCK), status=403, headers={"server": "AkamaiGHost"}, url="https://shop.example/")
        self.assertTrue(r.blocked, r.summary)

    def test_cookie_jar_and_headers_shapes(self):
        r = cd.detect_html("<p>hi</p>", cookies=[Cookie("_px3"), Cookie("_pxhd")])
        self.assertEqual(r.detections[0].id, "perimeterx")
        r = cd.detect_html("<p>hi</p>", headers=[("X-DataDome", "protected"), ("Set-Cookie", "datadome=1; Path=/")])
        self.assertEqual(r.detections[0].id, "datadome")
        r = cd.detect_html("<p>hi</p>", headers={"x-datadome": ["a", "b"]})
        self.assertEqual(r.detections[0].id, "datadome")

    def test_min_confidence(self):
        html = '<div class="captcha-wrap"></div><img src="/captcha.png">'
        self.assertTrue(cd.detect_html(html).captcha)
        self.assertFalse(cd.detect_html(html, min_confidence=0.9).captcha)

    def test_custom_signatures(self):
        mine = [
            {
                "id": "acme-check",
                "name": "ACME bot check",
                "kind": "challenge-page",
                "title": [(r"^acme says hold on", 0.9)],
                "elements": ["#acme-check", {"sel": "form", "attr": ["action"], "re": r"/acme/verify", "w": 0.9}],
                "refine": lambda d, x: dict(d, subtype="js") if x.short else None,
            }
        ]
        r = cd.detect_html('<title>ACME says hold on</title><div id="acme-check"></div>', signatures=mine)
        self.assertEqual((r.detections[0].id, r.detections[0].subtype, r.challenge_page), ("acme-check", "js", True))
        # built-ins plus your own
        r = cd.detect_html(RECAPTCHA + '<div id="acme-check"></div><title>ACME says hold on</title>', signatures=cd.SIGNATURES + mine)
        self.assertEqual({d.id for d in r.detections}, {"recaptcha", "acme-check"})

    def test_signatures_are_complete(self):
        ids = [s["id"] for s in cd.SIGNATURES]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(sum(1 for s in cd.SIGNATURES if not s["generic"]), 69)

    def test_broken_html(self):
        for html in ["<", '<div class="g-recaptcha', "<script>", "<img src=captcha.png" * 1000, "&#99999999999;", "&#xD800;", "<a b='c>"]:
            cd.detect_html(html)

    def test_large_page_is_fast(self):
        big = "<html><body>" + '<div class="row"><a href="/x">link</a><img src="/a.png"><span>text text text</span></div>' * 20000 + "</body></html>"
        t = time.time()
        cd.detect_html(big)
        self.assertLess(time.time() - t, 3)

    def test_async(self):
        r = asyncio.run(cd.detect_response_async(FakeRequests(RECAPTCHA)))
        self.assertTrue(r.captcha)


class Clients(unittest.TestCase):
    """Real client objects, built without network."""

    def test_requests(self):
        try:
            import requests
        except ImportError:
            self.skipTest("requests not installed")
        res = requests.models.Response()
        res.status_code = 403
        res._content = CF_CHALLENGE.encode()
        res.headers = requests.structures.CaseInsensitiveDict({"Server": "cloudflare", "CF-Mitigated": "challenge"})
        res.url = "https://shop.example/"
        res.encoding = "utf-8"
        r = cd.detect_response(res)
        self.assertTrue(r.challenge_page)
        self.assertEqual(r.detections[0].confidence, 0.99)

    def test_httpx(self):
        try:
            import httpx
        except ImportError:
            self.skipTest("httpx not installed")
        res = httpx.Response(200, headers=[("x-datadome", "protected"), ("set-cookie", "datadome=1")], text=DATADOME, request=httpx.Request("GET", "https://shop.example/p"))
        r = cd.detect_response(res)
        self.assertTrue(r.challenge_page, r.summary)
        self.assertEqual(r.url, "https://shop.example/p")


class Cli(unittest.TestCase):
    def run_cli(self, *args, stdin=None):
        p = subprocess.run([sys.executable, "-m", "captcha_detector", *args], input=stdin, capture_output=True, env={"PYTHONPATH": str(Path(cd.__file__).parent.parent), "PATH": "/usr/bin:/bin"})
        return p.returncode, p.stdout.decode(), p.stderr.decode()

    def test_stdin_json(self):
        body = json.dumps({"ok": True, "result": {"status_code": 403, "html": CF_CHALLENGE}}).encode()
        code, out, _ = self.run_cli("-", "--json", "--fail", stdin=body)
        self.assertEqual(code, 1)
        self.assertTrue(json.loads(out)["challenge_page"])

    def test_file_and_text(self):
        f = Path(__file__).parent / "_tmp_page.html"
        f.write_text(RECAPTCHA)
        try:
            code, out, _ = self.run_cli(str(f))
            self.assertEqual(code, 0)
            self.assertIn("reCAPTCHA", out)
            self.assertIn("widget/v2-checkbox", out)
        finally:
            f.unlink()

    def test_bad_input(self):
        code, _, err = self.run_cli("/nope/missing")
        self.assertEqual(code, 2)
        self.assertIn("Not a URL or a file", err)

    def test_in_process(self):
        f = Path(__file__).parent / "_tmp_cf.html"
        f.write_text(CF_CHALLENGE)
        buf = io.StringIO()
        try:
            with redirect_stdout(buf):
                code = cli_main([str(f), "--json"])
        finally:
            f.unlink()
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(buf.getvalue())["detections"][0]["id"], "cloudflare-challenge")


if __name__ == "__main__":
    unittest.main()


class Aiohttp(unittest.TestCase):
    def test_aiohttp(self):
        try:
            import aiohttp
        except ImportError:
            self.skipTest("aiohttp not installed")
        from tests.test_selenium import serve

        srv, origin = serve({"/dd": DATADOME})

        async def go():
            async with aiohttp.ClientSession() as s:
                async with s.get(origin + "/dd") as resp:
                    with self.assertRaises(TypeError):
                        cd.detect_response(resp)
                    return await cd.detect_response_async(resp)

        try:
            r = asyncio.run(go())
        finally:
            srv.shutdown()
        self.assertTrue(r.challenge_page, r.summary)
        self.assertEqual(r.url, origin + "/dd")
