import json
import os
from collections import namedtuple
from unittest.mock import patch

from marshmallow import ValidationError
from vcr_unittest import VCRTestCase

from pygitguardian import GGClient, ScanResultSchema
from pygitguardian.config import DEFAULT_BASE_URI, DOCUMENT_SIZE_THRESHOLD_BYTES


FILENAME = ".env"
DOCUMENT = """
    import urllib.request
    url = 'http://jen_barber:correcthorsebatterystaple@cake.gitguardian.com/isreal.json'
    response = urllib.request.urlopen(url)
    consume(response.read())"
"""
EXAMPLE_RESPONSE = """
[{
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
},
{
  "policy_break_count": 1,
  "policies": [
    "Filenames",
    "File extensions",
    "Secrets detection"
  ],
  "policy_breaks": [
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
},
{
  "policy_break_count": 0,
  "policies": [
    "Filenames",
    "File extensions",
    "Secrets detection"
  ],
  "policy_breaks": []
}

]
"""

VCR_BASE_CONF = {
    "decode_compressed_response": True,
    "ignore_localhost": True,
    "match_on": ["url", "method", "body"],
    "serializer": "yaml",
    "record_mode": "once",
    "filter_headers": [
        ("authorization", "Token XXX"),
        ("apikey", None),
        ("private-token", None),
    ],
}


class TestClient(VCRTestCase):
    def _get_vcr_kwargs(self, **kwargs):
        return {**kwargs, **VCR_BASE_CONF}

    def setUp(self):
        self.live_server = os.environ.get("TEST_LIVE_SERVER", "false").lower() == "true"
        if not self.live_server:
            super().setUp()

        self.token = os.environ.get("TEST_LIVE_SERVER_TOKEN", "zetoken")
        self.base_uri = os.environ.get(
            "TEST_LIVE_SERVER_URL", "https://api.gitguardian.com"
        )

        self.client = GGClient(base_uri=self.base_uri, token=self.token)

    def test_client_creation(self):
        TestEntry = namedtuple(
            "TestEntry", "name, token, uri, user_agent, timeout, exception"
        )
        test_data = [
            TestEntry(
                name="valid prefix",
                token="validtokenforsure",
                uri="http://fake_uri",
                user_agent="custom",
                timeout=30.0,
                exception=None,
            ),
            TestEntry(
                name="valid - no trailing /",
                token="validtokenforsure",
                uri="https://api.gitguardian.com",
                user_agent="custom",
                timeout=30.0,
                exception=None,
            ),
            TestEntry(
                name="valid - trailing /",
                token="validtokenforsure",
                uri="https://api.gitguardian.com/",
                user_agent="custom",
                timeout=30.0,
                exception=None,
            ),
            TestEntry(
                name="No baseuri",
                token="validtokenforsure",
                uri=None,
                user_agent="custom",
                timeout=30.0,
                exception=None,
            ),
            TestEntry(
                name="No baseuri",
                token=None,
                uri=None,
                user_agent="custom",
                timeout=30.0,
                exception=TypeError,
            ),
            TestEntry(
                name="invalid prefix",
                token="validtokenforsure",
                uri="fake_uri",
                user_agent=None,
                timeout=30.0,
                exception=ValueError,
            ),
        ]
        for entry in test_data:
            with self.subTest(msg=entry.name):
                if entry.exception is not None:
                    with self.assertRaises(entry.exception):
                        client = GGClient(
                            token=entry.token,
                            base_uri=entry.uri,
                            user_agent=entry.user_agent,
                            timeout=entry.timeout,
                        )
                else:
                    client = GGClient(
                        base_uri=entry.uri,
                        token=entry.token,
                        user_agent=entry.user_agent,
                        timeout=entry.timeout,
                    )

                if entry.exception is None:
                    if entry.uri:
                        self.assertEqual(client.base_uri, entry.uri)
                    else:
                        self.assertEqual(client.base_uri, DEFAULT_BASE_URI)
                    self.assertEqual(client.token, entry.token)
                    self.assertTrue(
                        entry.user_agent in client.session.headers["User-Agent"],
                    )
                    self.assertEqual(client.timeout, entry.timeout)
                    self.assertEqual(
                        client.session.headers["Authorization"],
                        "Token {0}".format(entry.token),
                    )

    def test_health_check(self):
        health, status_code = self.client.health_check()
        self.assertEqual(status_code, 200)
        self.assertEqual(health.detail, "Valid API key.")
        self.assertEqual(str(health), "200:Valid API key.")
        self.assertEqual(bool(health), True)
        if not self.live_server:
            self.assertEqual(len(self.cassette), 1)
            self.assertEqual(
                self.cassette.requests[0].uri, "https://api.gitguardian.com/v1/health"
            )

    def test_assert_content_type(self):
        with self.assertRaises(TypeError):
            self.client.get(endpoint="/docs/static/logo.png", schema=None, version=None)

    def test_content_scan(self):
        scan_result, status_code = self.client.content_scan(
            filename=FILENAME, document=DOCUMENT
        )
        self.assertEqual(type(repr(scan_result)), str)
        self.assertEqual(type(str(scan_result)), str)
        self.assertEqual(status_code, 200)
        example_dict = json.loads(EXAMPLE_RESPONSE)[0]
        scan_dict = json.loads(ScanResultSchema().dumps(scan_result))

        self.assertEqual(
            all(elem in example_dict["policies"] for elem in scan_dict["policies"]),
            True,
        )
        self.assertEqual(scan_result.has_secrets, True)
        self.assertEqual(scan_result.policy_break_count, 2)

        if not self.live_server:
            self.assertEqual(len(self.cassette), 1)
            self.assertEqual(
                self.cassette.requests[0].uri, "https://api.gitguardian.com/v1/scan"
            )

    def test_multi_content_scan(self):
        TestEntry = namedtuple("TestEntry", "name, input, expected")
        test_data = [
            TestEntry(
                "with breaks",
                [
                    {"filename": FILENAME, "document": DOCUMENT},
                    {"document": DOCUMENT},
                    {"filename": "normal", "document": "normal"},
                ],
                EXAMPLE_RESPONSE,
            ),
            TestEntry("max size array", [{"document": "valid"}] * 20, None),
        ]

        for entry in test_data:
            with self.subTest(msg=entry.name):
                scan_results, status_code = self.client.multi_content_scan(entry.input)
                self.assertEqual(status_code, 200)
                self.assertEqual(type(scan_results), list)
                example_dict = json.loads(EXAMPLE_RESPONSE)
                for i, scan_result in enumerate(scan_results):
                    if entry.expected:
                        self.assertEqual(
                            all(
                                elem in example_dict[i]["policies"]
                                for elem in scan_result.policies
                            ),
                            True,
                        )
                        self.assertEqual(
                            scan_result.policy_break_count,
                            example_dict[i]["policy_break_count"],
                        )

                if not self.live_server:
                    self.assertEqual(len(self.cassette), 2)
                    self.assertEqual(
                        self.cassette.requests[0].uri,
                        "https://api.gitguardian.com/v1/multiscan",
                    )

    @patch("pygitguardian.config.DOCUMENT_SIZE_THRESHOLD_BYTES", 20)
    def test_content_scan_exceptions(self):
        TestEntry = namedtuple("TestEntry", "name, input, exception, regex")
        test_data = [
            TestEntry(
                "too large file",
                "a" * (DOCUMENT_SIZE_THRESHOLD_BYTES + 1),
                ValidationError,
                "file exceeds the maximum allowed size",
            ),
            TestEntry(
                "invalid type",
                "dwhewe\x00ddw",
                ValidationError,
                "document has null characters",
            ),
        ]

        for entry in test_data:
            with self.subTest(msg=entry.name):
                with self.assertRaisesRegex(entry.exception, entry.regex):
                    self.client.content_scan(entry.input)

    def test_multi_content_exceptions(self):
        TestEntry = namedtuple("TestEntry", "name, input, exception")
        test_data = [
            TestEntry("too large array", [{"document": "valid"}] * 21, ValueError),
            TestEntry("invalid type", [("tuple"), {"document": "valid"}], TypeError),
        ]

        for entry in test_data:
            with self.subTest(msg=entry.name):
                with self.assertRaises(entry.exception):
                    self.client.multi_content_scan(entry.input)
