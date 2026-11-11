"""Refine steps: a port of the `refine(d, x)` functions in src/signatures.js.

Each takes a detection dict and the page context, and returns the detection (with its variant, kind or visibility
worked out) or None to drop a weak match. The context is engine.Context (HTML mode: dom is False, any_visible() is
None, global_() is False), so the branches that need a live page give the same answers as the JS engine in HTML mode.
"""

import re

I = re.I

CAPTCHA_IMG = re.compile(
    r"captch|kaptcha|check_?code|verif(?:y|ication)_?(?:code|img|image|pic)|valid(?:ate)?_?code|(?:^|[^a-z])v_?code|secur(?:e|ity)_?code_?img|auth_?code|image_?code|img_?code|pic_?code|rand_?code|(?:^|[^a-z])yzm(?:[^a-z]|$)|securimage",
    I,
)
NOT_CAPTCHA_IMG = re.compile(r"logo|icon|badge|sprite|avatar|banner|screenshot|thumb|favicon", I)
_SVG = re.compile(r"\.svg(?:[?#]|$)", I)


def _j(*vals):
    """[a, b, c].join(' ') as JavaScript does it (null and undefined become '')."""
    return " ".join("" if v is None else str(v) for v in vals)


def captcha_images(x):
    """Images that look like a captcha to solve (not a logo, an icon or an illustration of one)."""
    out = []
    for n in x.query("img") + x.query("canvas"):
        a = _j(n.attr("src"), n.attr("id"), n.attr("class"), n.attr("alt"), n.attr("name"), n.attr("title"))
        src = n.attr("src") or ""
        if CAPTCHA_IMG.search(a) and not NOT_CAPTCHA_IMG.search(a) and not _SVG.search(src):
            out.append(n)
    return out


def _ev(d, *types):
    return any(e["type"] in types for e in d["evidence"])


def _details(d, **kw):
    d["details"] = dict(d.get("details") or {}, **kw)


# ───────────────────────────── Widgets ─────────────────────────────

_RC_ANCHOR = re.compile(r"/recaptcha/(?:api2|enterprise)/anchor", I)
_RC_BFRAME = re.compile(r"/recaptcha/(?:api2|enterprise)/bframe", I)
_RC_SIZE_INV = re.compile(r"[?&]size=invisible", I)
_RC_V3 = re.compile(r"/recaptcha/(?:api|enterprise)\.js\?(?:[^#]*&)?render=(?!explicit\b|onload\b)[\w-]{20,}", I)
_RC_ENT = re.compile(r"/recaptcha/enterprise", I)
_RC_OWN = re.compile(r"\.g-recaptcha|grecaptcha-badge")


def recaptcha(d, x):
    # hCaptcha's reCAPTCHA compatibility mode adds a g-recaptcha-response textarea and window.grecaptcha.
    if x.has("hcaptcha") and not any(e["type"] in ("scripts", "frames", "inline") or _RC_OWN.search(e["value"]) for e in d["evidence"]):
        return None
    anchors = x.frames(_RC_ANCHOR)
    bframes = x.frames(_RC_BFRAME)
    checkbox = [f for f in anchors if not _RC_SIZE_INV.search(f["src"])]
    invisible_anchor = any(_RC_SIZE_INV.search(f["src"]) for f in anchors)
    widgets = x.query(".g-recaptcha")
    invisible_widget = any(re.search(r"invisible", n.attr("data-size") or "", I) for n in widgets)
    v3 = x.script(_RC_V3)
    enterprise = x.script(_RC_ENT) or any("/enterprise/" in f["src"] for f in anchors) or x.global_("grecaptcha.enterprise")
    d["name"] = "reCAPTCHA Enterprise" if enterprise else "reCAPTCHA"
    if checkbox:
        d["subtype"] = "v2-checkbox"
        d["visible"] = x.any_visible(checkbox)
    elif invisible_widget or (invisible_anchor and not v3):
        d["subtype"] = "v2-invisible"
        d["kind"] = "invisible"
        d["visible"] = False if x.dom else None
    elif v3 or invisible_anchor:
        d["subtype"] = "v3"
        d["kind"] = "invisible"
        d["visible"] = False if x.dom else None
    elif widgets:
        d["subtype"] = "v2-checkbox"
        d["visible"] = x.any_visible(widgets)
    else:
        d["subtype"] = "v2"
        d["visible"] = False if x.dom else None
    if bframes and x.any_visible(bframes):
        d["visible"] = True
        _details(d, challenge_open=True)
    return d


def hcaptcha(d, x):
    checkbox = x.frames(re.compile(r"[#&]frame=checkbox(?:&|$)|hcaptcha-checkbox\.html", I))
    invisible_frame = x.frames(re.compile(r"[#&]frame=checkbox-invisible", I))
    challenge = x.frames(re.compile(r"[#&]frame=challenge|hcaptcha-challenge\.html", I))
    widgets = x.query(".h-captcha")
    invisible = len(invisible_frame) > 0 or any(re.search(r"invisible", n.attr("data-size") or "", I) for n in widgets)
    if invisible and not checkbox:
        d["kind"] = "invisible"
        d["subtype"] = "invisible"
        d["visible"] = False if x.dom else None
    else:
        d["subtype"] = "checkbox"
        if checkbox:
            d["visible"] = x.any_visible(checkbox)
        elif widgets:
            d["visible"] = x.any_visible(widgets)
    if challenge and x.any_visible(challenge):
        d["visible"] = True
        _details(d, challenge_open=True)
    return d


def turnstile(d, x):
    boxes = x.query(".cf-turnstile")
    inputs = x.query('input[name="cf-turnstile-response"]')
    frames = [f for f in x.frames(re.compile(r"challenges\.cloudflare\.com", I)) if f.get("el")]
    if frames:
        d["visible"] = x.any_visible(frames)
    elif boxes:
        d["visible"] = x.any_visible(boxes)
    elif inputs and x.dom:
        d["visible"] = any(x.visible_el(getattr(n, "parent", None)) for n in inputs)
    if any(re.search(r"interaction-only|execute", n.attr("data-appearance") or "", I) or re.search(r"invisible", n.attr("data-size") or "", I) for n in boxes):
        d["subtype"] = "interaction-only"
    else:
        d["subtype"] = "managed"
    return d


def geetest(d, x):
    v4 = x.script(re.compile(r"gcaptcha4|/v4/|gt4", I)) or len(x.query(".geetest_box")) > 0 or x.global_("initGeetest4") or bool(re.search(r"initGeetest4", x.inline))
    d["subtype"] = "v4" if v4 else "v3"
    return d


def aws_waf(d, x):
    captcha = (
        x.script(re.compile(r"captcha(?:-sdk)?\.awswaf\.com|\.captcha\.awswaf", I))
        or len(x.query("awswaf-captcha")) > 0
        or x.global_("AwsWafCaptcha")
        or bool(re.search(r"AwsWafCaptcha", x.inline))
        or bool(re.search(r"captcha", x.header("x-amzn-waf-action"), I))
    )
    challenge = bool(re.search(r"\bgokuProps\b", x.inline)) or x.global_("gokuProps") or bool(re.search(r"challenge", x.header("x-amzn-waf-action"), I))
    if captcha:
        d["kind"] = "challenge-page" if x.short and challenge else "widget"
        d["subtype"] = "image-grid"
        if d["kind"] == "challenge-page":
            d["visible"] = True
    elif challenge:
        d["name"] = "AWS WAF Challenge"
        d["kind"] = "challenge-page"
        d["subtype"] = "silent-challenge"
        d["visible"] = True
    else:
        d["name"] = "AWS WAF Bot Control"
        d["kind"] = "protection"
    return d


def aliyun_captcha(d, x):
    if re.search(r"_____tmd_____/punish", x.url, I):
        d["kind"] = "challenge-page"
        d["visible"] = True
    return d


# ───────────────────────────── Challenge and block pages ─────────────────────────────


def cloudflare_challenge(d, x):
    # 'Performance & security by Cloudflare' and the server header alone are on every Cloudflare error page.
    if d["confidence"] < 0.6:
        return None
    d["subtype"] = "turnstile" if x.has("turnstile") else "js-challenge"
    return d


def cloudflare_block(d, x):
    if x.has("cloudflare-challenge") or d["confidence"] < 0.6:
        return None
    return d


def datadome(d, x):
    return None if x.has("datadome-captcha") else d


def datadome_captcha(d, x):
    interstitial = len(x.frames(re.compile(r"/interstitial/", I))) > 0 or bool(re.search(r"""['"]?rt['"]?\s*:\s*['"]i['"]""", x.inline)) or x.global_("dd.rt") == "i"
    d["subtype"] = "interstitial" if interstitial else "slider"
    if not x.short and not interstitial:
        # A captcha frame inside a normal page: the overlay variant.
        d["kind"] = "widget"
        d["visible"] = x.any_visible(x.frames(re.compile(r"captcha-delivery\.com", I)))
    else:
        d["visible"] = True
    return d


def perimeterx(d, x):
    return None if x.has("perimeterx-captcha") else d


def perimeterx_captcha(d, x):
    if x.short or d["kind"] != "challenge-page":
        d["visible"] = True
    if not x.short:
        d["kind"] = "widget"
        d["visible"] = x.any_visible(x.query("#px-captcha"))
    return d


def akamai_bot_manager(d, x):
    return None if x.has("akamai-challenge") else d


def akamai_block(d, x):
    return None if d["confidence"] < 0.6 else d


def imperva(d, x):
    return None if x.has("imperva-challenge") or x.has("imperva-abp") else d


def kasada(d, x):
    if x.status == 429 or (x.dom is False and x.text_length < 200 and re.search(r"ips\.js", " ".join(e["value"] for e in d["evidence"]))):
        d["kind"] = "challenge-page"
        d["subtype"] = "silent-challenge"
        d["visible"] = True
    return d


def f5_asm(d, x):
    if re.search(r"what code is in the image", x.text, I):
        d["name"] = "F5 BIG-IP ASM CAPTCHA"
        d["kind"] = "challenge-page"
        d["subtype"] = "text-image"
        d["visible"] = True
    elif d["confidence"] < 0.6:
        d["kind"] = "protection"
    return d


def sucuri(d, x):
    if re.search(r"sucuri_cloudproxy_js", x.inline):
        d["kind"] = "challenge-page"
        d["subtype"] = "js-challenge"
        d["visible"] = True
    elif re.search(r"access denied", x.title + " " + x.text, I) and x.short:
        d["kind"] = "block-page"
    return d


def ddos_guard(d, x):
    if any(e["type"] in ("title", "elements") or re.search(r"check\.ddos-guard|well-known/ddos-guard", e["value"], I) for e in d["evidence"]):
        d["kind"] = "challenge-page"
        d["visible"] = True
    return d


def qrator(d, x):
    if x.short and _ev(d, "scripts"):
        d["kind"] = "challenge-page"
        d["visible"] = True
    return d


def stormwall(d, x):
    if x.short and d["confidence"] > 0.7:
        d["kind"] = "challenge-page"
        d["visible"] = True
    return d


def reblaze(d, x):
    if x.short and re.search(r"\brbzns\b", x.inline):
        d["kind"] = "challenge-page"
        d["visible"] = True
    return d


def radware(d, x):
    if re.search(r"validate\.perfdrive\.com", x.url, I) or re.search(r"radware bot manager", x.title, I) or (x.short and re.search(r"radware bot manager", x.text, I)):
        d["kind"] = "challenge-page"
        d["visible"] = True
    return d


def vk_captcha(d, x):
    if not re.search(r"not_robot_captcha", x.url, I):
        d["kind"] = "image"
        d["visible"] = x.any_visible(x.query("img"), lambda n: bool(re.search(r"captcha\.php", n.attr("src") or "", I)))
    return d


def baidu_captcha(d, x):
    if re.search(r"wappass\.baidu\.com/static/captcha", x.url, I) or x.short:
        d["kind"] = "challenge-page"
        d["visible"] = True
    return d


# ───────────────────────────── Catch-all rules ─────────────────────────────

_INPUT_EV = re.compile(r"^input")


def generic_image_captcha(d, x):
    imgs = captcha_images(x)
    other = any(e["type"] == "text" or (e["type"] == "elements" and _INPUT_EV.search(e["value"])) for e in d["evidence"])
    if not (imgs and other):
        return None
    d["visible"] = x.any_visible(imgs)
    return d


_NAMED_Q = re.compile(r"text_?captcha|captcha_?(?:answer|question|text)|question_?captcha", I)
_Q_INPUT = re.compile(r"captch|quiz|math|answer", I)


def generic_question(d, x):
    has_input = _ev(d, "elements")
    has_text = _ev(d, "text")
    # An answer field named like a text captcha, with no captcha image next to it.
    named = any(e["type"] == "elements" and _NAMED_Q.search(e["value"]) for e in d["evidence"])
    image = len(captcha_images(x)) > 0
    if not (has_input and has_text) and not (named and not image):
        return None
    inputs = [n for n in x.query("input") if _Q_INPUT.search(_j(n.attr("name"), n.attr("id")))]
    d["visible"] = x.any_visible(inputs)
    return d


_SLIDER = re.compile(r"slider[-_]?captcha|captcha[-_]?slider|slide[-_]?verify|verify[-_]?slide|slide[-_]?captcha|drag[-_]?verify|puzzle[-_]?captcha", I)


def generic_slider(d, x):
    d["visible"] = x.any_visible(x.query("div"), lambda n: bool(_SLIDER.search((n.attr("class") or "") + " " + (n.attr("id") or ""))))
    return d


_CAPTCHA = re.compile(r"captcha", I)


def generic_captcha(d, x):
    nodes = [n for t in ("div", "form", "img", "canvas", "iframe") for n in x.query(t) if _CAPTCHA.search(_j(n.attr("id"), n.attr("class"), n.attr("title"), n.attr("src")))]
    d["visible"] = x.any_visible(nodes + x.frames(_CAPTCHA))
    return d


def short_only(d, x):
    return d if x.short else None


REFINE = {
    "recaptcha": recaptcha,
    "hcaptcha": hcaptcha,
    "turnstile": turnstile,
    "geetest": geetest,
    "aws-waf": aws_waf,
    "aliyun-captcha": aliyun_captcha,
    "cloudflare-challenge": cloudflare_challenge,
    "cloudflare-block": cloudflare_block,
    "datadome": datadome,
    "datadome-captcha": datadome_captcha,
    "perimeterx": perimeterx,
    "perimeterx-captcha": perimeterx_captcha,
    "akamai-bot-manager": akamai_bot_manager,
    "akamai-block": akamai_block,
    "imperva": imperva,
    "kasada": kasada,
    "f5-asm": f5_asm,
    "sucuri": sucuri,
    "ddos-guard": ddos_guard,
    "qrator": qrator,
    "stormwall": stormwall,
    "reblaze": reblaze,
    "radware": radware,
    "vk-captcha": vk_captcha,
    "baidu-captcha": baidu_captcha,
    "generic-image-captcha": generic_image_captcha,
    "generic-question": generic_question,
    "generic-slider": generic_slider,
    "generic-captcha": generic_captcha,
    "generic-challenge": short_only,
    "generic-block": short_only,
}
