"""Command line: python -m captcha_detector <url | file.html | -> [options]  (also installed as `captcha-detector`)."""

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

from . import VERSION, detect_html, detect_response

UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"

EPILOG = """examples:
  captcha-detector https://www.google.com/recaptcha/api2/demo
  captcha-detector https://example.com --browser --json
  curl -s https://example.com | captcha-detector -
  curl -s "https://scraper-api.example/v1?url=..." | captcha-detector -   # HTML or a scraper API's JSON
"""


def from_url(url, a):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.9"})
    try:
        res = urllib.request.urlopen(req, timeout=30)
    except urllib.error.HTTPError as e:  # 403/429/503 pages are what we want to see
        res = e
    body = res.read()
    charset = res.headers.get_content_charset() or "utf-8"
    return detect_html(body.decode(charset, "replace"), url=res.geturl(), status=res.getcode(), headers=list(res.headers.items()), min_confidence=a.min)


def from_browser(url, a):
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise SystemExit("captcha-detector: --browser needs Playwright: pip install playwright && playwright install chromium")
    from .browser import detect_in_page

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not a.headful)
        try:
            page = browser.new_context(viewport={"width": 1280, "height": 900}).new_page()
            response = page.goto(url, wait_until="domcontentloaded", timeout=45000)
            try:
                page.wait_for_load_state("load", timeout=15000)
            except Exception:
                pass
            if a.wait > 0:
                page.wait_for_timeout(a.wait)
            return detect_in_page(page, response=response, min_confidence=a.min)
        finally:
            browser.close()


def show(r):
    tty = sys.stdout.isatty()

    def c(code, s):
        return "\x1b[%sm%s\x1b[0m" % (code, s) if tty else s

    head = c("33;1", "⚠ Captcha found") if r["captcha"] else c("31;1", "⛔ Blocked") if r["blocked"] else c("32;1", "✓ No captcha found")
    print(head + ("  " + c("2", r["url"]) if r["url"] else ""))
    if r["captcha"]:
        vis = "unknown (static HTML)" if r["visible"] is None else str(r["visible"]).lower()
        print(c("2", "  visible: %s   challenge page: %s" % (vis, str(r["challenge_page"]).lower())))
    for d in r["detections"]:
        bits = [d["vendor"], d["kind"] + ("/" + d["subtype"] if d["subtype"] else ""), "visible" if d["visible"] is True else "not visible" if d["visible"] is False else None, "%d%%" % int(d["confidence"] * 100 + 0.5)]
        print("  • %s %s" % (c("1", d["name"]), c("2", "— " + " · ".join(b for b in bits if b))))
        for e in d["evidence"][:4]:
            print(c("2", "      %s: %s%s" % (e["type"], e["value"], " (in frame)" if e.get("frame") else "")))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="captcha-detector", description="captcha-detector %s: does this page have a captcha?" % VERSION, epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", help="a URL, an HTML (or scraper API JSON) file, or - for stdin")
    ap.add_argument("--browser", action="store_true", help="open the page in a real browser (needs: pip install playwright) and check the live page and its frames")
    ap.add_argument("--headful", action="store_true", help="show the browser window (with --browser)")
    ap.add_argument("--wait", type=int, default=3000, metavar="MS", help="wait after the page loads, with --browser (default 3000)")
    ap.add_argument("--json", action="store_true", help="print the full result as JSON")
    ap.add_argument("--fail", action="store_true", help="exit with code 1 when a captcha is found")
    ap.add_argument("--min", type=float, default=0.5, metavar="0..1", help="minimum confidence (default 0.5)")
    ap.add_argument("--version", action="version", version=VERSION)
    a = ap.parse_args(argv)
    try:
        if a.input == "-":
            r = detect_response(sys.stdin.buffer.read(), min_confidence=a.min)
        elif re.match(r"^https?://", a.input, re.I):
            r = from_browser(a.input, a) if a.browser else from_url(a.input, a)
        elif os.path.exists(a.input):
            with open(a.input, "rb") as f:
                r = detect_response(f.read(), min_confidence=a.min)
        elif re.match(r"^[\w-]+(\.[\w-]+)+", a.input):
            url = "https://" + a.input
            r = from_browser(url, a) if a.browser else from_url(url, a)
        else:
            raise ValueError("Not a URL or a file: " + a.input)
    except SystemExit:
        raise
    except Exception as e:
        print("captcha-detector: %s" % e, file=sys.stderr)
        return 2
    if a.json:
        print(json.dumps(r, indent=2, ensure_ascii=False))
    else:
        show(r)
    return 1 if a.fail and r["captcha"] else 0


if __name__ == "__main__":
    sys.exit(main())
