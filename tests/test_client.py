import json
import os
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from unittest import TestCase

import requests

from pygitguardian import DocumentSchema, GGClient, ScanResultSchema
from pygitguardian.client import _BASE_URI


FILENAME = ".env"
DOCUMENT = """
    import urllib.request
    url = 'http://jen_barber:correcthorsebatterystaple@cake.gitguardian.com/isreal.json'
    response = urllib.request.urlopen(url)
    consume(response.read())"
"""
EXAMPLE_RESPONSE = """
{
  "policy_break_count": 2,
  "policies": [
    "Filenames",
    "File extensions",
    "Secrets detection"
  ],
  "policy_breaks": [
    {
      "type": ".env",
      "policy": "Filenames",
      "matches": [
        {
          "type": "filename",
          "match": ".env"
        }
      ]
    },
    {
      "type": "Basic Auth String",
      "policy": "Secrets detection",
      "matches": [
        {
          "type": "username",
          "match": "jen_barber",
          "index_start": 36,
          "index_end": 45,
          "line_start": 2,
          "line_end": 2
        },
        {
          "type": "password",
          "match": "correcthorsebatterystaple",
          "index_start": 47,
          "index_end": 71,
          "line_start": 2,
          "line_end": 2
        },
        {
          "type": "host",
          "match": "cake.gitguardian.com",
          "index_start": 73,
          "index_end": 92,
          "line_start": 2,
          "line_end": 2
        }
      ]
    }
  ]
}
"""


class MockAPIServer(BaseHTTPRequestHandler):
    def do_GET(self):
        request_path = self.path
        token = self.headers.get("authorization", "Token thisisaninvalidtoken")
        if token != "Token validtokenforsure":
            self.send_response(requests.codes.forbidden)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"detail": "Invalid API key."}).encode("utf-8"))
            return

        if request_path == "/v1/health":
            obj = json.dumps({"detail": "Valid API key."}).encode("utf-8")
        elif request_path == "/doc/static/logo.png":
            self.send_response(requests.codes.ok)
            self.send_header("Content-Type", "image/png")
            self.end_headers()
            self.wfile.write(
                json.dumps({"detail": "Should be an image."}).encode("utf-8")
            )
            return

        self.send_response(requests.codes.ok)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(obj)

    def do_POST(self):
        request_path = self.path

        if request_path == "/v1/scan":
            content_len = int(self.headers.get("content-length"))
            content = self.rfile.read(content_len)
            post_body = json.loads(content.decode("utf-8"))
            doc = DocumentSchema().load(post_body)
            example_req = DocumentSchema().load(
                {"filename": FILENAME, "document": DOCUMENT}
            )

            if str(example_req) == str(doc):
                scan_result = ScanResultSchema().load(json.loads(EXAMPLE_RESPONSE))
                obj = json.dumps(ScanResultSchema().dump(scan_result)).encode("utf-8")

        self.send_response(requests.codes.ok)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(obj)

    do_PUT = do_POST
    do_DELETE = do_GET


def get_free_port():
    s = socket.socket(socket.AF_INET, type=socket.SOCK_STREAM)
    s.bind(("localhost", 0))
    address, port = s.getsockname()
    s.close()
    return port


class TestClient(TestCase):
    @classmethod
    def setup_class(cls):
        cls.mock_server_port = get_free_port()
        cls.mock_server = HTTPServer(("localhost", cls.mock_server_port), MockAPIServer)

        cls.mock_server_thread = Thread(target=cls.mock_server.serve_forever)
        cls.mock_server_thread.setDaemon(True)
        cls.mock_server_thread.start()

    def setUp(self):
        live_server = os.environ.get("TEST_LIVE_SERVER", "False")
        token = os.environ.get("TEST_LIVE_SERVER_TOKEN")
        if live_server == "True":
            base_uri = os.environ.get(
                "TEST_LIVE_SERVER_URL", "http://127.0.0.1:5000/exposed"
            )
        else:
            base_uri = "http://localhost:{port}/".format(port=self.mock_server_port)
            token = "validtokenforsure"

        self.client = GGClient(base_uri=base_uri, token=token)

    def test_client_creation(self):
        test_data = [
            ("invalid prefix", "validtokenforsure", "fake_uri", None, 30.0, ValueError),
            (
                "valid prefix",
                "validtokenforsure",
                "http://fake_uri",
                "custom",
                30.0,
                None,
            ),
            ("No baseuri", "validtokenforsure", None, "custom", 30.0, None),
            ("No baseuri", None, None, "custom", 30.0, TypeError),
        ]
        for name, token, uri, user_agent, timeout, exception in test_data:
            with self.subTest(msg=name):
                if exception is not None:
                    with self.assertRaises(exception):
                        client = GGClient(
                            token=token,
                            base_uri=uri,
                            user_agent=user_agent,
                            timeout=timeout,
                        )
                else:
                    client = GGClient(
                        base_uri=uri,
                        token=token,
                        user_agent=user_agent,
                        timeout=timeout,
                    )

                if exception is None:
                    if uri:
                        self.assertEqual(client.base_uri, uri)
                    else:
                        self.assertEqual(client.base_uri, _BASE_URI)
                    self.assertEqual(client.token, token)
                    self.assertEqual(
                        client.session.headers["User-Agent"],
                        "pygitguardian {0}".format(user_agent),
                    )
                    self.assertEqual(client.timeout, timeout)
                    self.assertEqual(
                        client.session.headers["Authorization"],
                        "Token {0}".format(token),
                    )

    def test_health_check(self):
        health = self.client.health_check()
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.success, True)
        self.assertEqual(bool(health), True)
        self.assertEqual(bool(health), health.success)
        self.assertEqual(health.detail, "Valid API key.")
        self.assertEqual(str(health), "200:Valid API key.")

    def test_assert_content_type(self):
        with self.assertRaises(TypeError):
            self.client.get(endpoint="/doc/static/logo.png", schema=None, version=None)

    def test_content_scan(self):
        scan_result = self.client.content_scan(filename=FILENAME, document=DOCUMENT)
        self.assertEqual(type(repr(scan_result)), str)
        self.assertEqual(type(str(scan_result)), str)
        example_dict = json.loads(EXAMPLE_RESPONSE)
        scan_dict = json.loads(ScanResultSchema().dumps(scan_result))

        self.assertEqual(
            all(elem in example_dict["policies"] for elem in scan_dict["policies"]),
            True,
        )
        self.assertEqual(scan_result.has_secrets, True)
        self.assertEqual(scan_result.policy_break_count, 2)
        self.assertEqual(scan_result.status_code, 200)
