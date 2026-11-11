"""detect_response(): check what an HTTP client or a scraper API returned (port of detectResponse in engine.js)."""

import json
import re

from .engine import detect_html

_LOOKS_HTML = re.compile(r"<(?:!doctype|html|head|body|script|iframe|form|div|title|meta|noscript)\b", re.I)
_STATUS_KEY = re.compile(r"^(?:status|status_?code|http_?status(?:_?code)?|original_?status|target_?status)$", re.I)
_HEADERS_KEY = re.compile(r"^headers$", re.I)
_URL_KEY = re.compile(r"^(?:url|final_?url|resolved_?url)$", re.I)
_HTTP = re.compile(r"^https?:", re.I)
_JSONISH = re.compile(r"^\s*[\[{]")


def _unwrap_json(v):
    """A scraper API often wraps the page in JSON ({"html": ...}, {"result": {"content": ...}}). Find the longest
    string that looks like HTML, and the status/headers/url next to it."""
    best = [None, None]

    def walk(o, depth):
        if depth > 5:
            return
        items = o.items() if isinstance(o, dict) else enumerate(o) if isinstance(o, list) else ()
        for _k, x in items:
            if isinstance(x, str):
                if len(x) > 20 and _LOOKS_HTML.search(x) and (best[0] is None or len(x) > len(best[0])):
                    best[0], best[1] = x, o
            elif isinstance(x, (dict, list)) and x:
                walk(x, depth + 1)

    walk(v, 0)
    if best[0] is None:
        return None
    out = {"html": best[0]}
    parent = best[1]
    if isinstance(parent, dict):
        for k, x in parent.items():
            k = str(k)
            if _STATUS_KEY.search(k) and _num(x) is not None and 100 <= _num(x) <= 599:
                out["status"] = _num(x)
            elif _HEADERS_KEY.search(k) and isinstance(x, (dict, list)) and x:
                out["headers"] = x
            elif _URL_KEY.search(k) and isinstance(x, str) and _HTTP.search(x):
                out["url"] = x
    return out


def _num(x):
    if isinstance(x, bool):
        return None
    try:
        n = float(x)
    except (TypeError, ValueError):
        return None
    return int(n) if n == int(n) else n


def _from_body(body):
    html, extra = body, {}
    if isinstance(body, (bytes, bytearray)):
        body = html = bytes(body).decode("utf-8", "replace")
    if isinstance(body, (dict, list)):
        extra = _unwrap_json(body) or {}
        html = extra["html"] if "html" in extra else json.dumps(body, ensure_ascii=False, separators=(",", ":"))
    elif isinstance(body, str) and _JSONISH.search(body):
        try:
            found = _unwrap_json(json.loads(body))
        except ValueError:
            found = None
        if found:
            extra, html = found, found["html"]
    return {"html": "" if html is None else str(html), "status": extra.get("status"), "headers": extra.get("headers"), "url": extra.get("url")}


def _url_str(u):
    return "" if u is None else str(u)


def _read(obj):
    """Body, status, headers, url and cookies from a response object of a common Python HTTP client."""
    status = headers = url = cookies = None
    body = obj
    t = type(obj).__module__.split(".")[0]
    if isinstance(obj, (str, bytes, bytearray, dict, list)) or obj is None:
        return body, status, headers, url, cookies
    if t == "aiohttp":
        raise TypeError("aiohttp responses are read asynchronously: use `await detect_response_async(resp)` or pass `await resp.text()`")
    # requests, httpx, niquests, curl_cffi, scrapy, urllib3, urllib
    if hasattr(obj, "status_code"):
        status = obj.status_code
    elif hasattr(obj, "status"):
        status = obj.status
    elif hasattr(obj, "getcode"):
        status = obj.getcode()
    headers = getattr(obj, "headers", None)
    url = getattr(obj, "url", None)
    if url is None and hasattr(obj, "geturl"):
        url = obj.geturl()
    cookies = getattr(obj, "cookies", None)
    text = getattr(obj, "text", None)
    if callable(text):  # not a requests/httpx .text property
        text = None
    if isinstance(text, str):
        body = text
    elif hasattr(obj, "content") and isinstance(getattr(obj, "content", None), (bytes, bytearray)):
        body = obj.content
    elif hasattr(obj, "body") and isinstance(getattr(obj, "body", None), (bytes, bytearray, str)):
        body = obj.body
    elif hasattr(obj, "data") and isinstance(getattr(obj, "data", None), (bytes, bytearray, str)):
        body = obj.data  # urllib3
    elif hasattr(obj, "read"):
        body = obj.read()  # urllib.request
    return body, status, headers, url, cookies


def _check(body, status, headers, url, cookies, opts):
    b = _from_body(body)
    # Status and headers found next to the HTML inside the JSON belong to the target site: they win over the API's.
    return detect_html(
        b["html"],
        url=opts.get("url") or b["url"] or _url_str(url),
        status=opts["status"] if opts.get("status") is not None else b["status"] if b["status"] is not None else status,
        headers=opts.get("headers") or b["headers"] or headers,
        cookies=opts.get("cookies") if opts.get("cookies") is not None else cookies,
        min_confidence=opts.get("min_confidence", 0.5),
        signatures=opts.get("signatures"),
    )


def detect_response(response, url=None, status=None, headers=None, cookies=None, min_confidence=0.5, signatures=None):
    """Check what an HTTP client or a scraper API returned.

    response  a requests / httpx / curl_cffi / scrapy / urllib3 / urllib response, an HTML string or bytes,
              or the JSON a scraper API sent (str, dict or list). HTML wrapped in JSON is found on its own,
              with the status code, headers and URL next to it.
    url       the page you asked for (not the scraper API's address)
    status, headers, cookies  override what the response says

    Most scraper APIs answer 200 whatever the site did; that is fine, the page itself gives a captcha away.
    """
    body, st, hd, u, ck = _read(response)
    opts = {"url": url, "status": status, "headers": headers, "cookies": cookies, "min_confidence": min_confidence, "signatures": signatures}
    return _check(body, st, hd, u, ck, opts)


async def detect_response_async(response, url=None, status=None, headers=None, cookies=None, min_confidence=0.5, signatures=None):
    """detect_response() for async clients: aiohttp (reads `await resp.text()`), httpx.AsyncClient responses and
    anything detect_response() takes."""
    opts = {"url": url, "status": status, "headers": headers, "cookies": cookies, "min_confidence": min_confidence, "signatures": signatures}
    if type(response).__module__.split(".")[0] == "aiohttp":
        body = await response.text(errors="replace")
        ck = [c.key for c in response.cookies.values()] if getattr(response, "cookies", None) else None
        return _check(body, response.status, response.headers, response.url, ck, opts)
    body, st, hd, u, ck = _read(response)
    return _check(body, st, hd, u, ck, opts)
