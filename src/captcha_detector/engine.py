"""HTML engine: a line-by-line port of src/engine.js (HTML mode) so both give the same answers.

The signature database is shared: signatures.json is generated from src/signatures.js by `npm run build`.
The refine steps (code, not data) live in refine.py.
"""

import json
import math
import re
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

from . import refine as _refine

VERSION = "1.0.1"

CAPTCHA_KINDS = {"widget", "invisible", "image", "question", "challenge-page"}
TYPES = ["scripts", "frames", "elements", "inline", "globals", "urls", "title", "text", "cookies", "headers", "status"]
DEFAULT_WEIGHT = {
    "scripts": 0.9, "frames": 0.95, "elements": 0.85, "inline": 0.8, "globals": 0.85, "urls": 0.8,
    "title": 0.65, "text": 0.6, "cookies": 0.5, "headers": 0.75, "status": 0.25,
}
#: A bot-check page is short: wording only counts on pages with less visible text than this.
SHORT_PAGE = 6000
MAX_TEXT = 200000
MAX_INLINE = 600000

# ───────────────────────────── Signatures ─────────────────────────────

_DATA = json.loads((Path(__file__).parent / "signatures.json").read_text(encoding="utf-8"))
#: Version of the JavaScript captcha-detector the signature database was exported from.
SIGNATURES_VERSION = _DATA["version"]


def _rx(src, flags=""):
    return re.compile(src, re.I if "i" in flags else 0)


def _load(raw):
    """Turn a JSON signature (from signatures.json) into the shape the engine uses (compiled patterns)."""
    sig = {k: raw.get(k) for k in ("id", "name", "vendor", "kind", "subtype", "site", "generic")}
    sig["refine"] = _refine.REFINE.get(raw["id"]) if raw.get("refine") else None
    if raw.get("refine") and not sig["refine"]:  # pragma: no cover - parity guard
        raise ImportError("no Python refine for signature %r" % raw["id"])
    for t in TYPES:
        if t not in raw:
            continue
        out = []
        for e in raw[t]:
            if t == "status":
                out.append(e)
            elif t == "headers":
                out.append((e["name"].lower(), _rx(e["re"], e["flags"]), e.get("w")))
            elif t == "elements":
                if "re" in e:
                    out.append(({"sel": e["sel"], "attr": e["attr"], "re": _rx(e["re"], e["flags"])}, e.get("w")))
                else:
                    out.append((e["sel"], e.get("w")))
            elif t == "cookies":
                out.append((_rx(e["re"], e["flags"]) if "re" in e else e["name"], e.get("w")))
            else:
                out.append((_rx(e["re"], e["flags"]), e.get("w"), bool(e.get("any"))))
        sig[t] = out
    return sig


#: The built-in signatures (compiled). Each is a dict: id, name, vendor, kind, subtype, site, generic, refine and
#: matcher lists. See README "Add a provider" to write your own.
SIGNATURES = [_load(s) for s in _DATA["signatures"]]


def _compile_entry(t, e):
    """Normalise one matcher entry: (pattern, weight, any). Accepts the compiled built-ins and user signatures
    written in Python (regex strings or re.Pattern, optionally as (pattern, weight[, 'any']) tuples)."""
    if t == "status":
        return (e, None, False)
    if t == "headers":
        name, p = e[0], e[1]
        return ((str(name).lower(), p if hasattr(p, "search") else re.compile(p, re.I)), e[2] if len(e) > 2 else None, False)
    if t == "elements":
        if isinstance(e, dict):
            p = dict(e)
            if not hasattr(p["re"], "search"):
                p["re"] = re.compile(p["re"], re.I)
            return (p, e.get("w"), False)
        if isinstance(e, (tuple, list)):
            p = e[0]
            if isinstance(p, dict):
                p = dict(p)
                if not hasattr(p["re"], "search"):
                    p["re"] = re.compile(p["re"], re.I)
            return (p, e[1] if len(e) > 1 else None, False)
        return (e, None, False)
    if t == "cookies":
        p, w = (e[0], e[1] if len(e) > 1 else None) if isinstance(e, (tuple, list)) else (e, None)
        return (p, w, False)
    if t == "globals":
        return (None, None, False)
    p, w, a = e, None, False
    if isinstance(e, (tuple, list)):
        p, w, a = e[0], e[1] if len(e) > 1 else None, (len(e) > 2 and e[2] in (True, "any"))
    if not hasattr(p, "search"):
        p = re.compile(p, re.I)
    return (p, w, a)


def _compile(signatures):
    out = []
    for sig in signatures:
        m = {}
        for t in TYPES:
            if sig.get(t) and t != "globals":
                m[t] = [_compile_entry(t, e) for e in sig[t]]
        out.append((sig, m))
    return out


_COMPILED = None


def _get_compiled(signatures=None):
    global _COMPILED
    if signatures is not None and signatures is not SIGNATURES:
        return _compile(signatures)
    if _COMPILED is None:
        _COMPILED = _compile(SIGNATURES)
    return _COMPILED


# ───────────────────────────── Small helpers ─────────────────────────────

_WS = re.compile(r"\s+")


def _short(s, n=140):
    s = _WS.sub(" ", "" if s is None else str(s)).strip()
    return s[: n - 1] + "…" if len(s) > n else s


def _text(v):
    if isinstance(v, bytes):
        return v.decode("utf-8", "replace")
    return str(v)


def lower_headers(h):
    """Headers as {lower-case name: value}; repeated headers are joined with a newline.
    Accepts a dict, a list of pairs, requests/httpx/aiohttp/scrapy header objects."""
    out = {}
    if not h:
        return out

    def add(k, v):
        k = _text(k).lower()
        v = "\n".join(_text(x) for x in v) if isinstance(v, (list, tuple)) else _text(v)
        out[k] = out[k] + "\n" + v if out.get(k) else v

    if hasattr(h, "multi_items"):  # httpx
        for k, v in h.multi_items():
            add(k, v)
    elif hasattr(h, "getall") and hasattr(h, "keys"):  # aiohttp / multidict
        for k in dict.fromkeys(h.keys()):
            add(k, list(h.getall(k)))
    elif isinstance(h, (list, tuple)):
        for k, v in h:
            add(k, v)
    elif hasattr(h, "items"):
        items = h.items()
        for k, v in items:
            if v is not None:
                add(k, v)
    return out


def _cookie_names(inp, headers):
    names = []

    def push(n):
        if n and n not in names:
            names.append(n)

    def from_pairs(s):
        for part in str(s).split(";"):
            push(part.split("=")[0].strip())

    if isinstance(inp, str):
        from_pairs(inp)
    elif isinstance(inp, (list, tuple)):
        for c in inp:
            if isinstance(c, str):
                from_pairs(c)
            elif isinstance(c, dict) and c.get("name"):
                push(c["name"])
            elif getattr(c, "name", None):
                push(c.name)
    elif isinstance(inp, dict):
        for k in inp:
            push(k)
    elif inp is not None and hasattr(inp, "__iter__"):  # http.cookiejar.CookieJar / RequestsCookieJar
        for c in inp:
            if isinstance(c, str):  # httpx.Cookies yields names
                push(c)
            elif getattr(c, "name", None):
                push(c.name)
    if headers and headers.get("set-cookie"):
        for line in headers["set-cookie"].split("\n"):
            from_pairs(line.split(";")[0])
    return names


# ───────────────────────────── Mini selector engine ─────────────────────────────

_SEL_RE = re.compile(
    r"""\s*(?:(\*|[a-zA-Z][\w-]*)|#([\w-]+)|\.([\w-]+)|\[\s*([\w:-]+)\s*(?:([~^$*|]?=)\s*(?:"([^"]*)"|'([^']*)'|([^\]\s]+))\s*(i)?)?\s*\]|:not\(([^)]*)\))"""
)
_selector_cache = {}


def _parse_compound(src):
    c = {"tag": None, "ids": [], "classes": [], "attrs": [], "nots": []}
    src = src.strip()
    pos = 0
    while pos < len(src):
        m = _SEL_RE.match(src, pos)
        if not m or m.end() == pos:
            raise ValueError("Unsupported selector: " + src)
        if m.group(1):
            c["tag"] = None if m.group(1) == "*" else m.group(1).lower()
        elif m.group(2):
            c["ids"].append(m.group(2))
        elif m.group(3):
            c["classes"].append(m.group(3))
        elif m.group(4):
            v = m.group(6) if m.group(6) is not None else m.group(7) if m.group(7) is not None else m.group(8)
            c["attrs"].append({"name": m.group(4).lower(), "op": m.group(5) or None, "value": v, "i": bool(m.group(9))})
        elif m.group(10) is not None:
            c["nots"].append(_parse_compound(m.group(10)))
        pos = m.end()
    return c


def _parse_selector(sel):
    p = _selector_cache.get(sel)
    if p is None:
        p = _selector_cache[sel] = [_parse_compound(x) for x in sel.split(",")]
    return p


def _attr_matches(a, actual):
    if actual is None:
        return False
    if not a["op"]:
        return True
    v, s = a["value"], actual
    if a["i"]:
        v, s = v.lower(), s.lower()
    op = a["op"]
    if op == "=":
        return s == v
    if op == "*=":
        return v != "" and v in s
    if op == "^=":
        return v != "" and s.startswith(v)
    if op == "$=":
        return v != "" and s.endswith(v)
    if op == "~=":
        return v in _WS.split(s)
    if op == "|=":
        return s == v or s.startswith(v + "-")
    return False


def _compound_matches(c, tag):
    if c["tag"] and c["tag"] != tag["tag"]:
        return False
    for i in c["ids"]:
        if tag["attrs"].get("id") != i:
            return False
    if c["classes"]:
        lst = _WS.split(tag["attrs"].get("class") or "")
        for cl in c["classes"]:
            if cl not in lst:
                return False
    for a in c["attrs"]:
        if not _attr_matches(a, tag["attrs"].get(a["name"])):
            return False
    for n in c["nots"]:
        if _compound_matches(n, tag):
            return False
    return True


# ───────────────────────────── HTML collector ─────────────────────────────

_ENTITIES = {"amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'", "nbsp": "\xa0", "#39": "'"}
_ENTITY_RE = re.compile(r"&(#x[0-9a-f]+|#\d+|[a-z]+\d*);", re.I)


def _decode_one(m):
    e = m.group(1)
    if e[0] == "#":
        try:
            code = int(e[2:], 16) if e[1] in "xX" else int(e[1:], 10)
            return chr(code)
        except (ValueError, OverflowError):
            return m.group(0)
    v = _ENTITIES.get(e.lower())
    return v if v is not None else m.group(0)


def _decode(s):
    return _ENTITY_RE.sub(_decode_one, str(s))


def _resolve_url(u, base):
    """new URL(u, base).href, closely enough for matching."""
    if not u:
        return ""
    u = u.strip()
    if not base:
        return u
    try:
        r = urljoin(base, u)
        p = urlsplit(r)
        if not p.scheme or (p.scheme in ("http", "https") and not p.netloc):
            return u if not p.scheme else r
        path = p.path or ("/" if p.scheme in ("http", "https") else "")
        return urlunsplit((p.scheme.lower(), p.netloc.lower(), path, p.query, p.fragment))
    except ValueError:
        return u


_COMMENTS = re.compile(r"<!--[\s\S]*?-->")
_BASE = re.compile(r"""<base\b[^>]*\bhref\s*=\s*["']?([^"'\s>]+)""", re.I)
_RAW = re.compile(r"<(script|style|template|textarea|noscript|xmp)\b([^>]*)>([\s\S]*?)</\1\s*>", re.I)
_SRC_ATTR = re.compile(r"\bsrc\s*=", re.I)
_TAG = re.compile(r"""<([a-zA-Z][a-zA-Z0-9:-]*)((?:\s+[^\s"'>/=]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'=<>`]+))?)*)\s*/?>""")
_ATTR = re.compile(r"""([^\s"'>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?""")
_PRELOAD = re.compile(r"\b(?:preload|modulepreload|prefetch)\b", re.I)
_AS_SCRIPT = re.compile(r"^(?:script|)$", re.I)
_TITLE = re.compile(r"<title\b[^>]*>([\s\S]*?)</title\s*>", re.I)
_HEAD = re.compile(r"<head\b[\s\S]*?</head\s*>", re.I)
_TITLES = re.compile(r"<title\b[\s\S]*?</title\s*>", re.I)
_BLOCK = re.compile(r"<(?:br|p|div|li|tr|h[1-6]|section|article|header|footer)\b[^>]*>", re.I)
_ANYTAG = re.compile(r"<[^>]+>")
_HSPACE = re.compile(r"[ \t\f\v\r\xa0]+")
_NL = re.compile(r"\s*\n\s*")


class Node:
    """An element found in the HTML: .tag and .attr(name) (None when missing)."""

    __slots__ = ("tag", "attrs", "el")

    def __init__(self, tag, attrs):
        self.tag = tag
        self.attrs = attrs
        self.el = None

    def attr(self, name):
        return self.attrs.get(name.lower())

    def __repr__(self):
        return "<Node %s %r>" % (self.tag, self.attrs)


class Snapshot:
    """What the engine looks at: built from HTML by snapshot_from_html()."""

    def __init__(self, **kw):
        self.__dict__.update(kw)
        self._cache = {}
        self._index = None

    def _build_index(self):
        by_tag, by_id, by_class, by_attr = {}, {}, {}, {}
        for i, t in enumerate(self.tags):
            by_tag.setdefault(t["tag"], []).append(i)
            for name, v in t["attrs"].items():
                by_attr.setdefault(name, []).append(i)
                if name == "id":
                    by_id.setdefault(v, []).append(i)
                elif name == "class":
                    for cl in set(_WS.split(v)):
                        by_class.setdefault(cl, []).append(i)
        self._index = (by_tag, by_id, by_class, by_attr)

    def _candidates(self, c):
        """Indexes of the tags that can match compound c (a superset; _compound_matches decides)."""
        if self._index is None:
            self._build_index()
        by_tag, by_id, by_class, by_attr = self._index
        lists = []
        if c["tag"]:
            lists.append(by_tag.get(c["tag"], ()))
        for i in c["ids"]:
            lists.append(by_id.get(i, ()))
        for cl in c["classes"]:
            lists.append(by_class.get(cl, ()))
        for a in c["attrs"]:
            lists.append(by_attr.get(a["name"], ()))
        if not lists:
            return range(len(self.tags))
        return min(lists, key=len)

    def query(self, sel):
        r = self._cache.get(sel)
        if r is None:
            hits = set()
            for c in _parse_selector(sel):
                tags = self.tags
                hits.update(i for i in self._candidates(c) if _compound_matches(c, tags[i]))
            r = [self.tags[i]["node"] for i in sorted(hits)]
            self._cache[sel] = r
        return r

    def is_visible(self, node):
        return None


def _status(v):
    if v is None:
        return None
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return int(f) if f == int(f) else f


def snapshot_from_html(html, url="", headers=None, status=None, cookies=None, **_):
    """Build a page snapshot from an HTML string."""
    html = "" if html is None else _text(html)
    hdrs = lower_headers(headers)
    no_comments = _COMMENTS.sub("", html)
    base = url or ""
    bt = _BASE.search(no_comments)
    if bt:
        base = _resolve_url(_decode(bt.group(1)), base)

    inline_parts = []
    inline_len = [0]

    def strip(m):
        tag, attrs, body = m.group(1), m.group(2), m.group(3)
        if tag.lower() == "script" and not _SRC_ATTR.search(attrs) and inline_len[0] < MAX_INLINE:
            inline_parts.append(body)
            inline_len[0] += len(body)
        return "<%s%s></%s>" % (tag, attrs, tag)

    stripped = _RAW.sub(strip, no_comments)

    tags = []
    for m in _TAG.finditer(stripped):
        attrs = {}
        if m.group(2):
            for a in _ATTR.finditer(m.group(2)):
                name = a.group(1).lower()
                if name not in attrs:
                    v = a.group(2) if a.group(2) is not None else a.group(3) if a.group(3) is not None else a.group(4) if a.group(4) is not None else ""
                    attrs[name] = _decode(v)
        t = {"tag": m.group(1).lower(), "attrs": attrs}
        t["node"] = Node(t["tag"], attrs)
        tags.append(t)

    scripts, frames = [], []
    for t in tags:
        a = t["attrs"]
        if t["tag"] == "script" and a.get("src"):
            scripts.append(_resolve_url(a["src"], base))
        elif t["tag"] == "link" and a.get("href") and _PRELOAD.search(a.get("rel") or "") and _AS_SCRIPT.search(a.get("as") or "script"):
            scripts.append(_resolve_url(a["href"], base))
        elif t["tag"] in ("iframe", "frame") and (a.get("src") or a.get("data-src")):
            frames.append({"src": _resolve_url(a.get("src") or a.get("data-src"), base), "title": a.get("title") or "", "name": a.get("name") or "", "node": t["node"]})

    tm = _TITLE.search(no_comments)
    title = _WS.sub(" ", _decode(tm.group(1))).strip() if tm else ""
    body_html = _TITLES.sub(" ", _HEAD.sub(" ", stripped, count=1))
    text = _decode(_ANYTAG.sub(" ", _BLOCK.sub("\n", body_html)))
    text = _NL.sub("\n", _HSPACE.sub(" ", text)).strip()[:MAX_TEXT]

    return Snapshot(
        mode="html",
        url=url or "",
        title=title,
        text=text,
        text_length=len(_WS.sub(" ", text)),
        scripts=scripts,
        resources=[],
        frames=frames,
        inline="\n;\n".join(inline_parts),
        cookies=_cookie_names(cookies, hdrs),
        headers=hdrs,
        status=_status(status),
        tags=tags,
    )


# ───────────────────────────── Matching ─────────────────────────────


def _m_scripts(p, s, any_):
    for u in s.scripts:
        if p.search(u):
            return {"value": u}
    return None


def _m_frames(p, s, any_):
    hit = [f for f in s.frames if f["src"] and p.search(f["src"])]
    if hit:
        return {"value": hit[0]["src"], "nodes": [f["node"] for f in hit]}
    return None


def _m_elements(p, s, any_):
    if isinstance(p, str):
        nodes = s.query(p)
        return {"value": p, "nodes": nodes} if nodes else None
    rx = p["re"]
    nodes = [n for n in s.query(p["sel"]) if any(n.attr(a) is not None and rx.search(n.attr(a)) for a in p["attr"])]
    if not nodes:
        return None
    n = nodes[0]
    a = next(x for x in p["attr"] if n.attr(x) is not None and rx.search(n.attr(x)))
    return {"value": '%s[%s="%s"]' % (p["sel"], a, _short(n.attr(a), 80)), "nodes": nodes}


def _m_inline(p, s, any_):
    m = p.search(s.inline)
    return {"value": m.group(0)} if m else None


def _m_globals(p, s, any_):
    return None  # browser only


def _m_urls(p, s, any_):
    return {"value": s.url} if s.url and p.search(s.url) else None


def _m_title(p, s, any_):
    return {"value": s.title} if s.title and p.search(s.title) else None


def _m_text(p, s, any_):
    if not any_ and s.text_length > SHORT_PAGE:
        return None
    m = p.search(s.text)
    return {"value": m.group(0)} if m else None


_TRAILING_SEP = re.compile(r"[_-]$")


def _m_cookies(p, s, any_):
    for c in s.cookies:
        if isinstance(p, str):
            ok = c.startswith(p) if _TRAILING_SEP.search(p) else c == p
        else:
            ok = bool(p.search(c))
        if ok:
            return {"value": c}
    return None


def _m_headers(p, s, any_):
    v = s.headers.get(p[0])
    return {"value": "%s: %s" % (p[0], _short(v, 60))} if v is not None and p[1].search(v) else None


def _m_status(p, s, any_):
    return {"value": str(p)} if s.status == p else None


_MATCH = {
    "scripts": _m_scripts, "frames": _m_frames, "elements": _m_elements, "inline": _m_inline, "globals": _m_globals,
    "urls": _m_urls, "title": _m_title, "text": _m_text, "cookies": _m_cookies, "headers": _m_headers, "status": _m_status,
}


def _score(m, s):
    evidence, nodes = [], []
    for t in TYPES:
        for p, w, any_ in m.get(t) or ():
            try:
                r = _MATCH[t](p, s, any_)
            except Exception:  # a broken pattern must not break detection
                r = None
            if not r:
                continue
            w = w if w is not None else DEFAULT_WEIGHT[t]
            value = _short(r["value"])
            same = next((e for e in evidence if e["type"] == t and e["value"] == value), None)
            if same:
                same["weight"] = max(same["weight"], w)
            else:
                evidence.append({"type": t, "value": value, "weight": w})
            nodes.extend(r.get("nodes") or ())
    if not evidence:
        return None
    if all(e["type"] == "status" for e in evidence):
        return None
    miss = 1.0
    for e in evidence:
        miss *= 1 - e["weight"]
    return {"evidence": evidence, "nodes": nodes, "confidence": 1 - miss}


class Context:
    """What a refine step can look at (HTML mode: no layout, no window)."""

    dom = False

    def __init__(self, s, alive):
        self._s = s
        self._alive = alive
        self.url = s.url
        self.title = s.title
        self.text = s.text
        self.text_length = s.text_length
        self.short = s.text_length <= SHORT_PAGE
        self.inline = s.inline
        self.status = s.status

    def has(self, sig_id):
        return sig_id in self._alive

    def header(self, name):
        return self._s.headers.get(name.lower()) or ""

    def query(self, sel):
        return self._s.query(sel)

    def frames(self, rx):
        return [f for f in self._s.frames if f["src"] and rx.search(f["src"])]

    def script(self, rx):
        return any(rx.search(u) for u in self._s.scripts)

    def global_(self, path):
        return False

    def any_visible(self, nodes, filter=None):
        return None

    def visible_el(self, el):
        return None


def _js_round(x):
    """Math.round(x * 100) / 100, as JavaScript rounds (half up, not half to even)."""
    return math.floor(x * 100 + 0.5) / 100


def _build(sig_id, sig, r, s, ctx):
    d = {
        "id": sig_id,
        "name": sig["name"],
        "vendor": sig.get("vendor") or None,
        "kind": sig["kind"],
        "subtype": sig.get("subtype") or None,
        "confidence": r["confidence"],
        "visible": None,
        "evidence": list(r["evidence"]),
        "site": sig.get("site") or None,
    }
    if d["kind"] == "challenge-page":
        d["visible"] = True
    fn = sig.get("refine")
    if fn:
        try:
            d = fn(d, ctx)
        except Exception:  # a refine bug must not break detection
            pass
        if not d:
            return None
    if d["kind"] in ("protection", "block-page"):
        d["visible"] = None
    d["confidence"] = _js_round(min(d["confidence"], 0.99))
    d["evidence"] = [{"type": e["type"], "value": e["value"]} for e in d["evidence"][:12]]
    return Detection(d)


_RANK = {"challenge-page": 0, "widget": 1, "image": 1, "question": 1, "invisible": 2, "block-page": 3, "protection": 4}


def _finalize(detections, url, mode):
    named = any(not d["id"].startswith("generic-") and d["kind"] != "protection" for d in detections)
    lst = [d for d in detections if not d["id"].startswith("generic-")] if named else list(detections)
    lst.sort(key=lambda d: (_RANK[d["kind"]], -d["confidence"]))
    captchas = [d for d in lst if d["kind"] in CAPTCHA_KINDS]
    known = any(d["visible"] is not None for d in captchas)
    if any(d["visible"] is True for d in captchas):
        visible = True
    elif known or mode == "dom":
        visible = False
    else:
        visible = None
    res = Result(
        captcha=len(captchas) > 0,
        visible=visible,
        challenge_page=any(d["kind"] == "challenge-page" for d in lst),
        blocked=any(d["kind"] == "block-page" for d in lst),
        detections=lst,
        summary="",
        url=url or "",
        mode=mode,
        version=VERSION,
    )
    res["summary"] = _summarize(res)
    return res


def _summarize(r):
    if not r["detections"]:
        return "No captcha found"
    parts = []
    for d in r["detections"]:
        s = d["name"] + (" (%s)" % d["subtype"] if d["subtype"] else "")
        if d["kind"] == "protection":
            s += " [bot protection, no captcha shown]"
        elif d["kind"] == "block-page":
            s += " [blocked]"
        elif d["visible"] is True:
            s += " [visible]"
        elif d["visible"] is False:
            s += " [invisible]" if d["kind"] == "invisible" else " [not shown]"
        parts.append(s)
    head = "Captcha found: " if r["captcha"] else "Blocked: " if r["blocked"] else "No captcha: "
    return head + ", ".join(parts)


class _AttrDict(dict):
    def __getattr__(self, k):
        try:
            return self[k]
        except KeyError:
            raise AttributeError(k)


class Detection(_AttrDict):
    """One product found: id, name, vendor, kind, subtype, confidence, visible, evidence, site (and details).
    A dict, also readable as attributes (d.kind)."""


class Result(_AttrDict):
    """captcha, visible, challenge_page, blocked, detections, summary, url, mode, version.
    A dict (json.dumps works), also readable as attributes (r.captcha)."""

    def __bool__(self):
        return True


def analyze(s, min_confidence=0.5, signatures=None, **_):
    """Run every signature on a snapshot from snapshot_from_html()."""
    lst = _get_compiled(signatures)
    raw = {}
    for sig, m in lst:
        r = _score(m, s)
        if r and r["confidence"] >= min_confidence:
            raw[sig["id"]] = (sig, r)
    # Refine twice: the first pass decides which matches survive, the second lets refine() see those survivors.
    alive = set(raw)
    out = []
    for _pass in range(2):
        ctx = Context(s, alive)
        out = []
        for sig_id, (sig, r) in raw.items():
            d = _build(sig_id, sig, r, s, ctx)
            if d:
                out.append(d)
        alive = {d["id"] for d in out}
    return _finalize(out, s.url, s.mode)


def detect_html(html, url="", headers=None, status=None, cookies=None, min_confidence=0.5, signatures=None):
    """Check an HTML string for captchas, bot-check pages and block pages.

    url      the page's address: resolves relative links, and is checked too
    headers  response headers (dict, list of pairs, requests/httpx/aiohttp headers)
    status   response status code
    cookies  "a=b; c=d", a list, a dict or a cookie jar (Set-Cookie headers are read too)

    Static HTML can't show widgets that scripts add later, and can't tell what is on screen (visible is None
    for widgets).
    """
    s = snapshot_from_html(html, url=url, headers=headers, status=status, cookies=cookies)
    return analyze(s, min_confidence=min_confidence, signatures=signatures)


# ───────────────────────────── Frames (browser helpers) ─────────────────────────────


def from_js(r):
    """Convert a result produced by the JavaScript build (camelCase) to the Python shape."""
    dets = []
    for d in r.get("detections") or []:
        d = dict(d)
        if isinstance(d.get("details"), dict):
            d["details"] = {("challenge_open" if k == "challengeOpen" else k): v for k, v in d["details"].items()}
        dets.append(Detection(d))
    return Result(
        captcha=r.get("captcha", False),
        visible=r.get("visible"),
        challenge_page=r.get("challengePage", r.get("challenge_page", False)),
        blocked=r.get("blocked", False),
        detections=dets,
        summary=r.get("summary", ""),
        url=r.get("url", ""),
        mode=r.get("mode", "dom"),
        version=r.get("version", VERSION),
    )


def merge_results(main, frames, signatures=None):
    """Combine a page's result with results from inside its frames: [{"url", "visible", "result"}]."""
    if "challengePage" in main:
        main = from_js(main)
    by_id = {}
    for d in main["detections"]:
        dd = Detection(d)
        dd["evidence"] = list(d["evidence"])
        by_id[d["id"]] = dd
    lst = _get_compiled(signatures)
    for f in frames:
        if not f or not f.get("result"):
            continue
        fr = f["result"]
        if "challengePage" in fr:
            fr = from_js(fr)
        furl = f.get("url") or ""
        owner = None
        if furl:
            for sig, m in lst:
                if sig["id"] in by_id and m.get("frames") and any(p.search(furl) for p, _w, _a in m["frames"]):
                    owner = sig
                    break
        fvis = f.get("visible")
        for d0 in fr["detections"]:
            if d0["kind"] == "block-page":
                continue
            if owner and d0["id"] != owner["id"]:
                continue
            if d0["id"] in ("generic-challenge", "generic-block"):
                continue
            d = Detection(d0)
            d["evidence"] = [dict(e, frame=furl) for e in d0["evidence"]]
            if d["kind"] == "challenge-page":
                d["kind"] = "widget"
                d["visible"] = fvis if fvis is not None else True
            elif d["kind"] not in ("protection", "invisible"):
                if fvis is False:
                    d["visible"] = False
                elif fvis is True and d["visible"] is not True:
                    d["visible"] = False if d["visible"] is False and any(e["type"] in ("elements", "frames") for e in d["evidence"]) else True
            cur = by_id.get(d["id"])
            if cur is None:
                d["frame"] = furl
                by_id[d["id"]] = d
                continue
            cur["confidence"] = max(cur["confidence"], d["confidence"])
            if d["visible"] is True and cur["kind"] != "invisible":
                cur["visible"] = True
            if not cur.get("subtype") and d.get("subtype"):
                cur["subtype"] = d["subtype"]
            if d.get("details"):
                cur["details"] = dict(cur.get("details") or {}, **d["details"])
            for e in d["evidence"]:
                if len(cur["evidence"]) < 16 and not any(x["value"] == e["value"] for x in cur["evidence"]):
                    cur["evidence"].append(e)
    return _finalize(list(by_id.values()), main["url"], main["mode"])
