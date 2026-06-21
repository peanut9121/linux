import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import service


class TargetParsingTests(unittest.TestCase):
    def test_accepts_tailscale_url_and_preserves_path(self):
        target = service.parse_target("http://100.107.82.7:8787/console?view=logs")

        self.assertEqual(target["host"], "100.107.82.7")
        self.assertEqual(target["port"], 8787)
        self.assertEqual(target["base_url"], "http://100.107.82.7:8787")
        self.assertEqual(target["requested_url"], "http://100.107.82.7:8787/console?view=logs")
        self.assertFalse(target["is_lab"])

    def test_accepts_private_host_and_port_without_scheme(self):
        target = service.parse_target("192.168.1.20:3000")

        self.assertEqual(target["scheme"], "http")
        self.assertEqual(target["port"], 3000)
        self.assertEqual(target["requested_url"], "http://192.168.1.20:3000/")

    def test_rejects_public_ip(self):
        with self.assertRaisesRegex(ValueError, "public internet targets"):
            service.parse_target("https://8.8.8.8")

    def test_rejects_embedded_credentials(self):
        with self.assertRaisesRegex(ValueError, "credentials"):
            service.parse_target("http://admin:secret@192.168.1.20:8080")

    def test_rejects_non_http_scheme(self):
        with self.assertRaisesRegex(ValueError, "only http and https"):
            service.parse_target("file://192.168.1.20/etc/passwd")

    def test_unknown_open_port_is_probed_as_http_and_https(self):
        target = service.parse_target("192.168.1.20")
        urls = service.candidate_urls(target, [{"port": 8787, "service": "msgsrvr"}])

        self.assertEqual(urls, ["http://192.168.1.20:8787/", "https://192.168.1.20:8787/"])


class InsecurePageHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        payload = b"<!doctype html><title>Private Test Console</title><h1>ready</h1>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Set-Cookie", "session=test")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        return


class PassiveWebAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), InsecurePageHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def test_reports_passive_header_cors_and_cookie_findings(self):
        url = f"http://127.0.0.1:{self.server.server_port}/"
        page = service.probe_url(url)
        findings, _ = service.audit_web_service(page, 1)
        titles = {item["title"] for item in findings}

        self.assertEqual(page["status"], 200)
        self.assertEqual(page["title"], "Private Test Console")
        self.assertIn("Content Security Policy is missing", titles)
        self.assertIn("CORS allows every origin", titles)
        self.assertIn("Cookie security attributes are incomplete", titles)
        self.assertTrue(all(item["actionable"] is False for item in findings))


if __name__ == "__main__":
    unittest.main()
