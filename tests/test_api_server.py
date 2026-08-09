import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib import request

from api.server import BackstabberAPIHandler


class APIServerThreadingTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        BackstabberAPIHandler.db_path = Path(self.tempdir.name) / "api.db"
        BackstabberAPIHandler.static_root = Path.cwd() / "frontend"
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), BackstabberAPIHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.httpd.server_port}"

    def tearDown(self):
        self.httpd.shutdown()
        self.thread.join(timeout=5)
        self.httpd.server_close()
        self.tempdir.cleanup()

    def test_threaded_requests_use_safe_database_connections(self):
        overview = self.get_json("/api/overview")
        self.assertEqual(overview["counts"]["engagements"], 0)

        created = self.post_json(
            "/api/engagements",
            {
                "actor": "test",
                "name": "Threaded API",
                "scope_cidrs": ["192.0.2.0/24"],
                "approval_required": True,
            },
        )

        engagements = self.get_json("/api/engagements")
        self.assertEqual(created["name"], "Threaded API")
        self.assertEqual(len(engagements), 1)
        self.assertEqual(engagements[0]["id"], created["id"])

    def get_json(self, path):
        with request.urlopen(self.base_url + path, timeout=5) as response:
            self.assertEqual(response.status, 200)
            return json.loads(response.read().decode("utf-8"))

    def post_json(self, path, payload):
        data = json.dumps(payload).encode("utf-8")
        req = request.Request(
            self.base_url + path,
            data=data,
            headers={"content-type": "application/json"},
            method="POST",
        )
        with request.urlopen(req, timeout=5) as response:
            self.assertEqual(response.status, 201)
            return json.loads(response.read().decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
