"""Browser helpers in a real Chromium (Playwright, sync and async). Pages are served offline with page.route().

Skipped when Playwright or its Chromium is not installed (pip install playwright && playwright install chromium).
"""

import asyncio
import unittest

import captcha_detector as cd

try:
    from playwright.sync_api import sync_playwright
    from playwright.async_api import async_playwright
except ImportError:  # pragma: no cover
    sync_playwright = None

ARKOSE_FRAME = "https://widget.other.test/frame.html"
TURNSTILE_FRAME = "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/b/turnstile/if/ov2/av0/rcv0/0/abc/0x4AAA/auto/fbE/normal/auto/"
CF_FRAME = "https://check.other.test/c.html"

PAGES = {
    "https://shop.test/": '<!doctype html><title>Shop</title><body><h1>Checkout</h1><iframe src="%s" width="420" height="300"></iframe></body>' % ARKOSE_FRAME,
    ARKOSE_FRAME: '<!doctype html><body><div id="arkose" style="width:400px;height:280px"></div><input type="hidden" name="fc-token"><script>window.ArkoseEnforcement=function(){}</script></body>',
    "https://contact.test/": '<!doctype html><title>Contact</title><body><form><div class="cf-turnstile" data-sitekey="x"><iframe src="%s" width="300" height="65"></iframe><input type="hidden" name="cf-turnstile-response"></div></form></body>' % TURNSTILE_FRAME,
    TURNSTILE_FRAME: '<!doctype html><title>Just a moment...</title><script>window._cf_chl_opt={cType:"chl_api_m"}</script><body><div id="challenge-stage">Verify you are human</div></body>',
    "https://home.test/": '<!doctype html><title>Home</title><body><p>Welcome</p><iframe src="%s" style="display:none"></iframe></body>' % CF_FRAME,
    CF_FRAME: '<!doctype html><title>Just a moment...</title><body><div id="challenge-running">Checking if the site connection is secure</div></body>',
    "https://signup.test/": '<!doctype html><title>Sign up</title><body><form><div class="g-recaptcha" style="width:304px;height:78px"></div></form><div style="display:none"><div class="h-captcha" style="width:303px;height:78px"></div><script>window.hcaptcha={render(){}}</script></div></body>',
    "https://late.test/": '<!doctype html><title>Late</title><body><p>Hi</p><script>setTimeout(()=>{const d=document.createElement("div");d.className="h-captcha";d.style.cssText="width:303px;height:78px";document.body.append(d);window.hcaptcha={render(){}}},700)</script></body>',
}


def _route(route):
    u = route.request.url
    if u == "https://blocked.test/":
        return route.fulfill(status=403, headers={"content-type": "text/html", "cf-mitigated": "challenge", "server": "cloudflare"}, body="<title>Just a moment...</title><p>Checking</p>")
    if u in PAGES:
        return route.fulfill(status=200, content_type="text/html", body=PAGES[u])
    return route.abort()


def _ids(r):
    return [d["id"] for d in r["detections"]]


@unittest.skipIf(sync_playwright is None, "playwright not installed")
class PlaywrightSync(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pw = sync_playwright().start()
        try:
            cls.browser = cls.pw.chromium.launch()
        except Exception as e:  # pragma: no cover
            cls.pw.stop()
            raise unittest.SkipTest("no Chromium for Playwright: %s" % str(e).splitlines()[0])
        cls.context = cls.browser.new_context()
        cls.context.route("**/*", _route)

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.pw.stop()

    def open(self, url):
        page = self.context.new_page()
        self.addCleanup(page.close)
        return page, page.goto(url)

    def test_cross_origin_frame(self):
        page, _ = self.open("https://shop.test/")
        self.assertFalse(cd.detect_in_page(page, frames=False)["captcha"], "the page script cannot see into the frame")
        r = cd.detect_in_page(page)
        d = next(d for d in r["detections"] if d["id"] == "arkose")
        self.assertIs(d["visible"], True)
        self.assertEqual(d["frame"], ARKOSE_FRAME)
        self.assertTrue(r.captcha)
        self.assertEqual(r.mode, "dom")

    def test_widget_frame_folded(self):
        page, _ = self.open("https://contact.test/")
        r = cd.detect_in_page(page)
        self.assertEqual(_ids(r), ["turnstile"])
        self.assertIs(r["detections"][0]["visible"], True)
        self.assertFalse(r.challenge_page)

    def test_hidden_frame_challenge(self):
        page, _ = self.open("https://home.test/")
        r = cd.detect_in_page(page)
        d = next(d for d in r["detections"] if d["id"] == "cloudflare-challenge")
        self.assertEqual(d["kind"], "widget")
        self.assertIs(d["visible"], False)
        self.assertFalse(r.challenge_page)

    def test_visibility(self):
        page, _ = self.open("https://signup.test/")
        r = cd.detect_in_page(page)
        by = {d["id"]: d for d in r["detections"]}
        self.assertIs(by["recaptcha"]["visible"], True)
        self.assertIs(by["hcaptcha"]["visible"], False)
        self.assertIs(r.visible, True)

    def test_response_headers(self):
        page, response = self.open("https://blocked.test/")
        r = cd.detect_in_page(page, response=response)
        d = next(d for d in r["detections"] if d["id"] == "cloudflare-challenge")
        self.assertTrue(any(e["type"] == "headers" and "cf-mitigated" in e["value"] for e in d["evidence"]))

    def test_wait_for_captcha(self):
        page, _ = self.open("https://late.test/")
        self.assertFalse(cd.detect_in_page(page).captcha)
        r = cd.wait_for_captcha(page, timeout=5, interval=0.2, visible=True)
        self.assertEqual(_ids(r), ["hcaptcha"])
        self.assertIs(r.visible, True)

    def test_no_global_left(self):
        page, _ = self.open("https://shop.test/")
        cd.detect_in_page(page)
        self.assertEqual(page.evaluate("typeof CaptchaDetector + typeof module"), "undefinedundefined")

    def test_browser_script_tag(self):
        page, _ = self.open("https://signup.test/")
        page.add_script_tag(content=cd.BROWSER_SCRIPT)
        r = cd.from_js(page.evaluate("CaptchaDetector.detect()"))
        self.assertIn("recaptcha", _ids(r))


@unittest.skipIf(sync_playwright is None, "playwright not installed")
class PlaywrightAsync(unittest.TestCase):
    def test_async_api(self):
        async def go():
            async with async_playwright() as p:
                try:
                    browser = await p.chromium.launch()
                except Exception as e:  # pragma: no cover
                    raise unittest.SkipTest("no Chromium for Playwright: %s" % str(e).splitlines()[0])
                ctx = await browser.new_context()
                await ctx.route("**/*", lambda route: asyncio.ensure_future(_route_async(route)))
                page = await ctx.new_page()
                resp = await page.goto("https://shop.test/")
                r1 = await cd.detect_in_page_async(page, response=resp)
                page2 = await ctx.new_page()
                await page2.goto("https://late.test/")
                r2 = await cd.wait_for_captcha_async(page2, timeout=5, interval=0.2)
                await browser.close()
                return r1, r2

        r1, r2 = asyncio.run(go())
        self.assertIn("arkose", _ids(r1))
        self.assertEqual(_ids(r2), ["hcaptcha"])


async def _route_async(route):
    u = route.request.url
    if u in PAGES:
        await route.fulfill(status=200, content_type="text/html", body=PAGES[u])
    else:
        await route.abort()


if __name__ == "__main__":
    unittest.main()


class _El:
    def __init__(self, h):
        self.h = h

    def get_attribute(self, name):
        return self.h.get_attribute(name)


class _SwitchTo:
    def __init__(self, drv):
        self.d = drv

    def default_content(self):
        self.d.frame = self.d.page.main_frame

    def frame(self, el):
        self.d.frame = el.h.content_frame()


class FakeSeleniumDriver:
    """Just enough of a Selenium WebDriver (execute_script with `arguments`, switch_to) on top of Playwright, to
    test detect_selenium()'s frame walking without chromedriver."""

    def __init__(self, page):
        self.page = page
        self.frame = page.main_frame
        self.switch_to = _SwitchTo(self)

    def execute_script(self, script, *args):
        fn = "(args) => (function () { %s }).apply(null, args)" % script
        handles = [a.h for a in args]
        h = self.frame.evaluate_handle(fn, handles)
        el = h.as_element()
        if el:
            return _El(el)
        props = h.get_properties() if h.evaluate("(x) => Array.isArray(x)") else None
        if props is not None:
            return [_El(p.as_element()) for _k, p in sorted(props.items(), key=lambda kv: int(kv[0])) if p.as_element()]
        return h.json_value()


@unittest.skipIf(sync_playwright is None, "playwright not installed")
class SeleniumLogic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        PlaywrightSync.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        PlaywrightSync.tearDownClass.__func__(cls)

    def drv(self, url):
        page = self.context.new_page()
        self.addCleanup(page.close)
        page.goto(url)
        return FakeSeleniumDriver(page)

    def test_cross_origin_frame(self):
        d = self.drv("https://shop.test/")
        self.assertFalse(cd.detect_selenium(d, frames=False).captcha)
        r = cd.detect_selenium(d)
        a = next(x for x in r.detections if x.id == "arkose")
        self.assertIs(a.visible, True)
        self.assertEqual(a.frame, ARKOSE_FRAME)
        self.assertIs(d.frame, d.page.main_frame, "back on the top-level page")

    def test_hidden_frame_and_folding(self):
        r = cd.detect_selenium(self.drv("https://home.test/"))
        c = next(x for x in r.detections if x.id == "cloudflare-challenge")
        self.assertEqual((c.kind, c.visible), ("widget", False))
        r = cd.detect_selenium(self.drv("https://contact.test/"))
        self.assertEqual(_ids(r), ["turnstile"])
