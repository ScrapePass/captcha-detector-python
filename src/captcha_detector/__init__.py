"""captcha-detector: does this web page have a captcha?

    from captcha_detector import detect_html, detect_response

    r = detect_response(requests.get(url), url=url)
    if r.captcha or r.challenge_page or r.blocked:
        print(r.summary)

Browser helpers (Playwright, Selenium) are in captcha_detector.browser and re-exported here.
"""

from .engine import (
    SIGNATURES,
    SIGNATURES_VERSION,
    VERSION,
    Detection,
    Result,
    analyze,
    detect_html,
    from_js,
    merge_results,
    snapshot_from_html,
)
from .response import detect_response, detect_response_async
from .browser import (
    BROWSER_SCRIPT,
    detect_in_page,
    detect_in_page_async,
    detect_selenium,
    expression,
    wait_for_captcha,
    wait_for_captcha_async,
)

__version__ = VERSION

__all__ = [
    "VERSION",
    "SIGNATURES",
    "SIGNATURES_VERSION",
    "Detection",
    "Result",
    "detect_html",
    "detect_response",
    "detect_response_async",
    "detect_in_page",
    "detect_in_page_async",
    "wait_for_captcha",
    "wait_for_captcha_async",
    "detect_selenium",
    "merge_results",
    "analyze",
    "snapshot_from_html",
    "from_js",
    "expression",
    "BROWSER_SCRIPT",
]
