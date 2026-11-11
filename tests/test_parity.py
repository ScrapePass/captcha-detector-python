"""The Python engine must give the same answers as the JavaScript engine.

tests/fixtures.json is written by `npm run build` in the JavaScript repo (scripts/build.mjs): every test page from test/cases.mjs and a few
extra inputs, each with the result of the JavaScript detectHtml()/detectResponse().
"""

import json
import unittest
from pathlib import Path

import captcha_detector as cd

FIX = json.loads((Path(__file__).parent / "fixtures.json").read_text(encoding="utf-8"))


def js_to_py(r):
    """The JS result in the Python shape (snake_case keys). `version` is each package's own, so it is left out."""
    r = json.loads(json.dumps(cd.from_js(r)))
    r.pop("version")
    return r


def py(r):
    r = json.loads(json.dumps(r))
    assert r.pop("version") == cd.VERSION
    return r


def py_opts(o):
    m = {"minConfidence": "min_confidence"}
    return {m.get(k, k): v for k, v in o.items()}


class Parity(unittest.TestCase):
    def test_version(self):
        self.assertEqual(FIX["version"], cd.SIGNATURES_VERSION, "fixtures.json and signatures.json come from one build")

    def test_pages(self):
        self.assertGreater(len(FIX["pages"]), 60)
        for p in FIX["pages"]:
            with self.subTest(p["name"]):
                got = py(cd.detect_html(p["html"], **py_opts(p["opts"])))
                self.assertEqual(got, js_to_py(p["result"]))

    def test_responses(self):
        for p in FIX["responses"]:
            with self.subTest(p["name"]):
                got = py(cd.detect_response(p["input"], **py_opts(p["opts"])))
                self.assertEqual(got, js_to_py(p["result"]))


if __name__ == "__main__":
    unittest.main()
