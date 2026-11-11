"""detect_selenium() in headless Chrome. Pages come from two local servers (two origins, so the frame is
cross-origin). Skipped unless selenium and chromedriver are installed."""

import shutil
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import captcha_detector as cd

try:
    from selenium import webdriver
except ImportError:  # pragma: no cover
    webdriver = None


def serve(pages):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            body = pages.get(self.path)
            self.send_response(200 if body else 404)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write((body or "").encode())

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%d" % srv.server_address[1]


@unittest.skipIf(webdriver is None or not shutil.which("chromedriver"), "selenium or chromedriver not installed")
class Selenium(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.frames_srv, frame_origin = serve({
            "/arkose.html": '<!doctype html><body><div id="arkose" style="width:400px;height:280px"></div><input type="hidden" name="fc-token"><script>window.ArkoseEnforcement=function(){}</script></body>',
            "/outer.html": None,
        })
        cls.frame_origin = frame_origin
        cls.page_srv, cls.origin = serve({
            "/shop.html": '<!doctype html><title>Shop</title><body><h1>Checkout</h1><iframe src="%s/arkose.html" width="420" height="300"></iframe></body>' % frame_origin,
            "/hidden.html": '<!doctype html><title>Home</title><body><p>Welcome</p><iframe src="%s/arkose.html" style="display:none"></iframe></body>' % frame_origin,
            "/signup.html": '<!doctype html><title>Sign up</title><body><form><div class="g-recaptcha" style="width:304px;height:78px"></div></form></body>',
        })
        opts = webdriver.ChromeOptions()
        opts.add_argument("--headless=new")
        cls.driver = webdriver.Chrome(options=opts)

    @classmethod
    def tearDownClass(cls):
        cls.driver.quit()
        cls.page_srv.shutdown()
        cls.frames_srv.shutdown()

    def test_cross_origin_frame(self):
        self.driver.get(self.origin + "/shop.html")
        self.assertFalse(cd.detect_selenium(self.driver, frames=False).captcha)
        r = cd.detect_selenium(self.driver)
        d = next(d for d in r.detections if d.id == "arkose")
        self.assertIs(d.visible, True)
        self.assertTrue(d.frame.startswith(self.frame_origin))
        # the driver is back on the page
        self.assertEqual(self.driver.execute_script("return document.title"), "Shop")

    def test_hidden_frame(self):
        self.driver.get(self.origin + "/hidden.html")
        r = cd.detect_selenium(self.driver)
        d = next(d for d in r.detections if d.id == "arkose")
        self.assertIs(d.visible, False)

    def test_page(self):
        self.driver.get(self.origin + "/signup.html")
        r = cd.detect_selenium(self.driver)
        self.assertEqual([d.id for d in r.detections], ["recaptcha"])
        self.assertIs(r.visible, True)


if __name__ == "__main__":
    unittest.main()
