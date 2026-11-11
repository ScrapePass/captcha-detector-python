"""Browser helpers: run the JavaScript build inside a real page (Playwright or Selenium), in every frame, and merge.

In a browser the detector sees what scripts added after load and knows what is on screen, so `visible` is
True/False instead of None. Cross-origin frames (reCAPTCHA, hCaptcha, Turnstile, DataDome) are checked from the
outside, which page scripts cannot do.
"""

import json
from pathlib import Path

from .engine import from_js, merge_results

#: Source of the browser build (exposes window.CaptchaDetector when loaded with a <script> tag).
BROWSER_SCRIPT = (Path(__file__).parent / "captcha-detector.js").read_text(encoding="utf-8")

MAX_FRAMES = 40

_FRAME_VISIBLE = """(e) => {
  const r = e.getBoundingClientRect();
  const cs = getComputedStyle(e);
  if (r.width < 10 || r.height < 10 || cs.display === 'none' || cs.visibility === 'hidden' || parseFloat(cs.opacity) < 0.05) return false;
  if (e.checkVisibility && !e.checkVisibility({ opacityProperty: true, visibilityProperty: true })) return false;
  return r.right + scrollX > 0 && r.bottom + scrollY > 0;
}"""


def _js_opts(min_confidence=None, deep=None, headers=None, status=None):
    o = {}
    if min_confidence is not None:
        o["minConfidence"] = min_confidence
    if deep is not None:
        o["deep"] = deep
    if headers:
        o["headers"] = {str(k).lower(): str(v) for k, v in dict(headers).items()}
    if status is not None:
        o["status"] = status
    return o


def expression(min_confidence=None, deep=None, headers=None, status=None):
    """A JavaScript expression that runs detect() in a page and returns the result, leaving no globals behind."""
    opts = json.dumps(_js_opts(min_confidence, deep, headers, status))
    return "(() => { const module = { exports: {} }; %s\n;const r = module.exports.detect(%s); return JSON.parse(JSON.stringify(r)); })()" % (BROWSER_SCRIPT, opts)


def _skip(url):
    return not url or url == "about:blank" or url.startswith("about:srcdoc")


# ───────────────────────────── Playwright (sync) ─────────────────────────────


def _pw_response(response):
    if response is None:
        return {}
    try:
        h = response.all_headers() if hasattr(response, "all_headers") else response.headers
        return {"status": response.status, "headers": h}
    except Exception:
        return {}


def _pw_frame_visible(frame):
    try:
        el = frame.frame_element()
        if not el or not el.evaluate(_FRAME_VISIBLE):
            return False
        parent = frame.parent_frame
        if parent is not None and parent.parent_frame is not None:
            return _pw_frame_visible(parent)
        return True
    except Exception:
        return None


def detect_in_page(page, response=None, frames=True, min_confidence=None, deep=None):
    """Detect captchas on a Playwright page (sync API), inside its frames too.

    response  the Response from page.goto(), so its status and headers are checked too
    frames    also look inside every frame, cross-origin ones included (default True)
    """
    info = _pw_response(response)
    main_frame = page.main_frame
    main = main_frame.evaluate(expression(min_confidence, deep, info.get("headers"), info.get("status")))
    if not frames:
        return from_js(main)
    results = []
    for frame in [f for f in page.frames if f != main_frame][:MAX_FRAMES]:
        url = frame.url
        if _skip(url):
            continue
        try:
            results.append({"url": url, "visible": _pw_frame_visible(frame), "result": frame.evaluate(expression(min_confidence, deep))})
        except Exception:
            pass  # detached or not ready
    return merge_results(main, results)


def wait_for_captcha(page, timeout=10.0, interval=0.5, visible=False, **kw):
    """Poll until a captcha appears (or with visible=True: until one is on screen), or `timeout` seconds pass.
    Returns the last result."""
    import time

    end = time.monotonic() + timeout
    while True:
        last = detect_in_page(page, **kw)
        if last["captcha"] and (not visible or last["visible"]):
            return last
        if time.monotonic() >= end:
            return last
        page.wait_for_timeout(interval * 1000)


# ───────────────────────────── Playwright (async) ─────────────────────────────


async def _pw_response_async(response):
    if response is None:
        return {}
    try:
        h = await response.all_headers() if hasattr(response, "all_headers") else response.headers
        return {"status": response.status, "headers": h}
    except Exception:
        return {}


async def _pw_frame_visible_async(frame):
    try:
        el = await frame.frame_element()
        if not el or not await el.evaluate(_FRAME_VISIBLE):
            return False
        parent = frame.parent_frame
        if parent is not None and parent.parent_frame is not None:
            return await _pw_frame_visible_async(parent)
        return True
    except Exception:
        return None


async def detect_in_page_async(page, response=None, frames=True, min_confidence=None, deep=None):
    """detect_in_page() for Playwright's async API."""
    import asyncio

    info = await _pw_response_async(response)
    main_frame = page.main_frame
    main = await main_frame.evaluate(expression(min_confidence, deep, info.get("headers"), info.get("status")))
    if not frames:
        return from_js(main)

    async def one(frame):
        url = frame.url
        if _skip(url):
            return None
        try:
            result, vis = await asyncio.gather(frame.evaluate(expression(min_confidence, deep)), _pw_frame_visible_async(frame))
            return {"url": url, "visible": vis, "result": result}
        except Exception:
            return None

    found = await asyncio.gather(*[one(f) for f in [f for f in page.frames if f != main_frame][:MAX_FRAMES]])
    return merge_results(main, [r for r in found if r])


async def wait_for_captcha_async(page, timeout=10.0, interval=0.5, visible=False, **kw):
    """wait_for_captcha() for Playwright's async API."""
    import asyncio
    import time

    end = time.monotonic() + timeout
    while True:
        last = await detect_in_page_async(page, **kw)
        if last["captcha"] and (not visible or last["visible"]):
            return last
        if time.monotonic() >= end:
            return last
        await asyncio.sleep(interval)


# ───────────────────────────── Selenium ─────────────────────────────

_SEL_FRAMES = "return Array.from(document.querySelectorAll('iframe, frame'))"
_SEL_VISIBLE = "return (%s)(arguments[0])" % _FRAME_VISIBLE


def detect_selenium(driver, frames=True, min_confidence=None, deep=None, max_depth=2):
    """Detect captchas with a Selenium WebDriver, inside its frames too (cross-origin ones included).

    Switches into each frame and back; the driver is left on the top-level page.
    """
    expr = "return " + expression(min_confidence, deep)
    driver.switch_to.default_content()
    main = driver.execute_script(expr)
    if not frames:
        return from_js(main)
    results = []

    def walk(path, parent_visible, depth):
        try:
            els = driver.execute_script(_SEL_FRAMES) or []
        except Exception:
            return
        for i in range(len(els)):
            if len(results) >= MAX_FRAMES:
                return
            try:
                els = driver.execute_script(_SEL_FRAMES) or []  # fresh handles after switching back
                el = els[i]
                url = el.get_attribute("src") or ""
                vis = bool(driver.execute_script(_SEL_VISIBLE, el)) and parent_visible
                driver.switch_to.frame(el)
                try:
                    url = driver.execute_script("return location.href") or url
                    if not _skip(url):
                        results.append({"url": url, "visible": vis, "result": driver.execute_script(expr)})
                    if depth < max_depth:
                        walk(path + [i], vis, depth + 1)
                finally:
                    driver.switch_to.default_content()
                    for j in path:
                        driver.switch_to.frame(driver.execute_script(_SEL_FRAMES)[j])
            except Exception:
                try:
                    driver.switch_to.default_content()
                    for j in path:
                        driver.switch_to.frame(driver.execute_script(_SEL_FRAMES)[j])
                except Exception:
                    return

    walk([], True, 1)
    driver.switch_to.default_content()
    return merge_results(main, results)
