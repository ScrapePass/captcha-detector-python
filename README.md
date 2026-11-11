# captcha-detector for Python

**Does this web page have a captcha?** The Python version of [captcha-detector](https://github.com/ScrapePass/captcha-detector): the same 69 named captcha and bot-check products plus catch-all rules, the same answers, zero dependencies.

- **Check what your scraper got back:** pass a `requests`, `httpx`, `aiohttp`, `curl_cffi`, Scrapy or urllib response, or the JSON a scraper API sent, and find out whether you got the real page or a captcha, a bot check or a block page.
- **Every kind:** checkbox widgets, invisible/score captchas, puzzles and sliders, proof-of-work, image captchas, math and text questions, full-page bot checks ("Just a moment…", "Press & Hold"), and access-denied pages.
- **Real browsers too:** Playwright (sync and async) and Selenium, cross-origin frames included, with `visible` telling you whether the captcha is on screen.

```bash
pip install captcha-detector
```

## Check a response

```python
import requests
from captcha_detector import detect_response

url = "https://shop.example/product/42"
res = requests.get(url)
r = detect_response(res)

if r.captcha or r.challenge_page or r.blocked:
    print("Not the real page:", r.summary)   # e.g. "Captcha found: DataDome captcha (slider) [visible]"
else:
    parse(res.text)
```

`detect_response()` takes:

| Input | Example |
|---|---|
| `requests` / `httpx` / `curl_cffi` / `niquests` response | `detect_response(requests.get(url))` |
| Scrapy response | `detect_response(response)` inside `parse()` |
| `urllib.request` / `urllib3` response | `detect_response(urlopen(url))` |
| `aiohttp` response | `await detect_response_async(resp)` |
| HTML as `str` or `bytes` | `detect_response(html, url=url)` |
| A scraper API's JSON (`str`, `dict` or `list`) | `detect_response(api_res.json(), url=target)` |

### Results from scraper APIs

HTML wrapped in JSON (`{"html": …}`, `{"result": {"content": …}}` and the like) is found on its own, along with the status code, headers and URL next to it.

```python
target = "https://shop.example/product/42"
res = requests.get("https://scraper-api.example/v1", params={"url": target, "key": KEY})
r = detect_response(res, url=target)
if r.captcha or r.challenge_page or r.blocked:
    ...  # retry with another proxy or provider, don't parse or store this one
```

Pass `url`, the page you asked the API to scrape, not the API's own address. Most scraper APIs answer `200` whatever the site did; that's fine, the page itself gives a captcha away. If your API reports the site's real status or headers somewhere else, pass them as `status=` and `headers=`.

## Check HTML

```python
from captcha_detector import detect_html

r = detect_html(html, url="https://shop.example/", status=403, headers={"server": "cloudflare"})
```

## In a real browser

Raw HTML only shows what the server sent, and can't tell what is on screen. In a browser the detector sees what scripts added and whether the captcha is visible.

```python
from playwright.sync_api import sync_playwright
from captcha_detector import detect_in_page, wait_for_captcha

with sync_playwright() as p:
    page = p.chromium.launch().new_page()
    response = page.goto("https://www.google.com/recaptcha/api2/demo")
    r = detect_in_page(page, response=response)      # checks every frame, cross-origin ones too
    print(r.summary)                                  # Captcha found: reCAPTCHA (v2-checkbox) [visible]

    r = wait_for_captcha(page, timeout=10, visible=True)   # wait until one is on screen
```

Async: `await detect_in_page_async(page)` and `await wait_for_captcha_async(page)`.

Selenium:

```python
from selenium import webdriver
from captcha_detector import detect_selenium

driver = webdriver.Chrome()
driver.get("https://www.google.com/recaptcha/api2/demo")
r = detect_selenium(driver)    # switches into each frame and back
```

Anything else that runs JavaScript can load `captcha_detector.BROWSER_SCRIPT` (it defines `window.CaptchaDetector`) or evaluate `captcha_detector.expression()`, then convert the result with `captcha_detector.from_js()`.

## The result

A `dict` (so `json.dumps` works) whose keys can also be read as attributes:

```python
{
  "captcha": True,          # a captcha or bot check is on the page (shown, invisible or not rendered yet)
  "visible": None,          # on screen right now: True/False in a browser, None for raw HTML
  "challenge_page": False,  # the whole page is a bot check
  "blocked": False,         # an access-denied page
  "detections": [{
      "id": "recaptcha", "name": "reCAPTCHA", "vendor": "Google",
      "kind": "widget",     # widget | invisible | image | question | challenge-page | block-page | protection
      "subtype": "v2-checkbox", "confidence": 0.99, "visible": None,
      "evidence": [{"type": "scripts", "value": "https://www.google.com/recaptcha/api.js"},
                   {"type": "elements", "value": ".g-recaptcha"}],
      "site": "https://developers.google.com/recaptcha",
  }],
  "summary": "Captcha found: reCAPTCHA (v2-checkbox)",
  "url": "https://shop.example/", "mode": "html", "version": "1.0.1",
}
```

`kind: "protection"` means a bot-protection service is loaded (DataDome, Akamai, PerimeterX…) but no captcha is shown; it does not set `captcha`. When the reCAPTCHA or hCaptcha image challenge is open, `details["challenge_open"]` is `True`.

Options for every function: `min_confidence` (0..1, default 0.5) and `signatures` (your own list; `SIGNATURES + mine` adds to the built-in ones).

## Command line

```bash
captcha-detector https://www.google.com/recaptcha/api2/demo
captcha-detector https://example.com --browser --json      # needs: pip install playwright
curl -s https://example.com | captcha-detector -
curl -s "https://scraper-api.example/v1?url=..." | captcha-detector -
```

Options: `--browser`, `--headful`, `--wait MS`, `--json`, `--fail` (exit code 1 when a captcha is found), `--min 0..1`. Also `python -m captcha_detector`.

## Add your own signature

```python
from captcha_detector import SIGNATURES, detect_html

acme = {
    "id": "acme-check", "name": "ACME bot check", "kind": "challenge-page",
    "title": [(r"^acme says hold on", 0.9)],                  # regex, or (regex, weight)
    "scripts": [r"cdn\.acme-shield\.example/"],
    "elements": ["#acme-check", {"sel": "form", "attr": ["action"], "re": r"/acme/verify", "w": 0.9}],
    "refine": lambda d, x: d if x.short else None,             # optional: adjust or drop a match
}
r = detect_html(html, signatures=SIGNATURES + [acme])
```

Matchers: `scripts`, `frames`, `elements` (CSS: tag, `#id`, `.class`, `[attr op "v" i]`, `:not()`), `inline` (inline script text), `urls`, `title`, `text` (short pages only, unless `(re, w, "any")`), `cookies`, `headers` (`(name, re, w)`), `status`. Matches combine into a confidence; the default threshold is 0.5.

To add a product for everyone, add it to `src/signatures.js` in the [JavaScript repository](https://github.com/ScrapePass/captcha-detector): the JavaScript and Python packages share one signature database.

## How it stays in step with the JavaScript package

The signature database (`signatures.json`), the browser script (`captcha-detector.js`) and the test fixtures (`tests/fixtures.json`) are generated from the [JavaScript repository](https://github.com/ScrapePass/captcha-detector), and the test suite checks that the Python engine gives exactly the same result as the JavaScript engine on every test page. `captcha_detector.SIGNATURES_VERSION` is the JavaScript version they came from.

To work on both, clone the two repositories side by side:

```bash
git clone https://github.com/ScrapePass/captcha-detector
git clone https://github.com/ScrapePass/captcha-detector-python
cd captcha-detector && npm install && npm run test:python   # rebuilds, exports to ../captcha-detector-python, runs its tests
```

A signature with a `refine()` step in JavaScript needs the same step in [`src/captcha_detector/refine.py`](src/captcha_detector/refine.py).

Tests on their own: `PYTHONPATH=src python3 -m unittest discover -s tests -t .`

## License

MIT
