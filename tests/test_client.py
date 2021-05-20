import json
from datetime import date
from typing import Any, Dict, List, Optional, Type
from unittest.mock import Mock, patch

import pytest
from marshmallow import ValidationError
from requests.models import Response

from pygitguardian import GGClient
from pygitguardian.client import is_ok, load_detail
from pygitguardian.config import (
    DEFAULT_BASE_URI,
    DOCUMENT_SIZE_THRESHOLD_BYTES,
    MULTI_DOCUMENT_LIMIT,
)
from pygitguardian.models import Detail, MultiScanResult, QuotaResponse, ScanResult

from .conftest import base_uri, my_vcr


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
        ("private-api_key", None),
    ],
}


@pytest.mark.parametrize(
    "api_key, uri, user_agent, timeout, exception ",
    [
        pytest.param(
            "validapi_keyforsure",
            "http://fake_uri",
            "custom",
            30.0,
            None,
            id="valid prefix",
        ),
        pytest.param(
            "validapi_keyforsure",
            "https://api.gitguardian.com",
            "custom",
            30.0,
            None,
            id="valid - no trailing /",
        ),
        pytest.param(
            "validapi_keyforsure",
            "https://api.gitguardian.com/",
            "custom",
            30.0,
            None,
            id="valid - trailing /",
        ),
        pytest.param(
            "validapi_keyforsure", None, "custom", 30.0, None, id="No baseuri"
        ),
        pytest.param(None, None, "custom", 30.0, TypeError, id="No baseuri"),
        pytest.param(
            "validapi_keyforsure",
            "fake_uri",
            None,
            30.0,
            ValueError,
            id="invalid prefix",
        ),
        pytest.param(
            "validapi_keyforsure",
            "https://api.gitguardian.com/",
            "custom",
            30.0,
            None,
            id="Custom headers",
        ),
    ],
)
def test_client_creation(
    api_key: str,
    uri: str,
    user_agent: str,
    timeout: float,
    exception: Type[Exception],
):
    if exception is not None:
        with pytest.raises(exception):
            client = GGClient(
                api_key=api_key,
                base_uri=uri,
                user_agent=user_agent,
                timeout=timeout,
            )
    else:
        client = GGClient(
            base_uri=uri,
            api_key=api_key,
            user_agent=user_agent,
            timeout=timeout,
        )

    if exception is None:
        if uri:
            assert client.base_uri == uri
        else:
            assert client.base_uri == DEFAULT_BASE_URI
        assert client.api_key == api_key
        assert client.timeout == timeout
        assert user_agent in client.session.headers["User-Agent"]
        assert client.session.headers["Authorization"] == "Token {0}".format(api_key)


@pytest.mark.parametrize(
    ("base_uries", "version", "endpoints_and_urls"),
    [
        (
            ("https://api.gitguardian.com",),
            "v1",
            (
                ("multiscan", "https://api.gitguardian.com/v1/multiscan"),
                ("scan", "https://api.gitguardian.com/v1/scan"),
            ),
        ),
        (
            (
                "https://gg-onprem-instance.company.com/exposed",
                "https://gg-onprem-instance.company.com/exposed/",
            ),
            "v1",
            (
                (
                    "multiscan",
                    "https://gg-onprem-instance.company.com/exposed/v1/multiscan",
                ),
                ("scan", "https://gg-onprem-instance.company.com/exposed/v1/scan"),
            ),
        ),
    ],
)
def test_client__url_from_endpoint(base_uries, version, endpoints_and_urls):
    for curr_base_uri in base_uries:
        client = GGClient(api_key="validapi_keyforsure", base_uri=curr_base_uri)
        for endpoint, expected_url in endpoints_and_urls:
            assert (
                client._url_from_endpoint(endpoint, version) == expected_url
            ), "Could not get the expected URL for base_uri=`{}`".format(base_uri)


@my_vcr.use_cassette
def test_health_check(client: GGClient):
    health = client.health_check()
    assert health.status_code == 200
    assert health.detail == "Valid API key."
    assert str(health) == "200:Valid API key."
    assert bool(health)
    assert health.success

    assert type(health.to_dict()) == dict
    assert type(health.to_json()) == str


@pytest.mark.parametrize(
    "name, to_scan, expected, has_secrets, has_policy_breaks",
    [
        pytest.param(
            "with_breaks",
            [
                {"filename": FILENAME, "document": DOCUMENT},
                {"document": DOCUMENT},
                {"filename": "normal", "document": "normal"},
            ],
            EXAMPLE_RESPONSE,
            True,
            True,
            id="with_breaks",
        ),
        pytest.param(
            "max_size_array",
            [{"document": "valid"}] * MULTI_DOCUMENT_LIMIT,
            None,
            False,
            False,
            id="max_size_array",
        ),
    ],
)
@my_vcr.use_cassette
def test_multi_content_scan(
    client: GGClient,
    name: str,
    to_scan: List[Dict[str, str]],
    expected: str,
    has_secrets: bool,
    has_policy_breaks: bool,
):
    with my_vcr.use_cassette(name + ".yaml"):
        multiscan = client.multi_content_scan(to_scan)

        assert multiscan.status_code == 200
        if not isinstance(multiscan, MultiScanResult):
            pytest.fail("multiscan is not a MultiScanResult")
            return

        assert type(multiscan.to_dict()) == dict
        assert type(multiscan.to_json()) == str
        assert type(repr(multiscan)) == str
        assert type(str(multiscan)) == str
        assert multiscan.has_secrets == has_secrets
        assert multiscan.has_policy_breaks == has_policy_breaks

        for i, scan_result in enumerate(multiscan.scan_results):
            if expected:
                example_dict = json.loads(expected)
                assert all(
                    elem in example_dict[i]["policies"] for elem in scan_result.policies
                )
                assert (
                    scan_result.policy_break_count
                    == example_dict[i]["policy_break_count"]
                )


@patch("pygitguardian.config.DOCUMENT_SIZE_THRESHOLD_BYTES", 20)
@pytest.mark.parametrize(
    "to_scan, exception, regex",
    [
        pytest.param(
            "a" * (DOCUMENT_SIZE_THRESHOLD_BYTES + 1),
            ValidationError,
            r"file exceeds the maximum allowed size",
            id="too large file",
        ),
        pytest.param(
            "dwhewe\x00ddw",
            ValidationError,
            r"document has null characters",
            id="invalid type",
        ),
    ],
)
def test_content_scan_exceptions(
    client: GGClient, to_scan: str, exception: Type[Exception], regex: str
):
    with pytest.raises(exception, match=regex):
        client.content_scan(to_scan)


@pytest.mark.parametrize(
    "to_scan, exception",
    [
        pytest.param([{"document": "valid"}] * 21, ValueError, id="too large array"),
        pytest.param([("tuple"), {"document": "valid"}], TypeError, id="invalid type"),
    ],
)
def test_multi_content_exceptions(
    client: GGClient, to_scan: List, exception: Type[Exception]
):
    with pytest.raises(exception):
        client.multi_content_scan(to_scan)


@my_vcr.use_cassette
def test_multi_content_not_ok():
    req = [{"document": "valid"}]
    client = GGClient(base_uri=base_uri, api_key="invalid")

    obj = client.multi_content_scan(req)

    assert obj.status_code == 401
    assert isinstance(obj, Detail)
    assert obj.detail == "Invalid API key."


@my_vcr.use_cassette
def test_content_not_ok():
    req = {"document": "valid", "filename": "valid"}
    client = GGClient(base_uri=base_uri, api_key="invalid")

    obj = client.content_scan(**req)

    assert obj.status_code == 401
    assert isinstance(obj, Detail)
    assert obj.detail == "Invalid API key."


@pytest.mark.parametrize(
    "name, to_scan, policy_break_count, has_secrets, has_policy_breaks",
    [
        pytest.param(
            "filename_secret",
            {"filename": FILENAME, "document": DOCUMENT},
            2,
            True,
            True,
            id="filename_secret",
        ),
        pytest.param("secret", {"document": DOCUMENT}, 1, True, True, id="secret"),
        pytest.param(
            "filename",
            {"filename": FILENAME, "document": "normal"},
            1,
            False,
            True,
            id="filename",
        ),
        pytest.param(
            "no_breaks",
            {"filename": "normal", "document": "normal"},
            0,
            False,
            False,
            id="no_breaks",
        ),
    ],
)
def test_content_scan(
    client: GGClient,
    name: str,
    to_scan: Dict[str, Any],
    has_secrets: bool,
    has_policy_breaks: bool,
    policy_break_count: int,
):
    with my_vcr.use_cassette(name + ".yaml"):
        scan_result = client.content_scan(**to_scan)
        assert type(repr(scan_result)) == str
        assert type(str(scan_result)) == str
        assert scan_result.status_code == 200
        if isinstance(scan_result, ScanResult):
            assert scan_result.has_secrets == has_secrets
            assert scan_result.has_policy_breaks == has_policy_breaks
            assert scan_result.policy_break_count == policy_break_count
        else:
            pytest.fail("returned should be a ScanResult")

        assert type(scan_result.to_dict()) == dict
        scan_result_json = scan_result.to_json()
        assert type(scan_result_json) == str
        assert type(json.loads(scan_result_json)) == dict


@my_vcr.use_cassette
def test_assert_content_type(client: GGClient):
    """
    GIVEN a response that's 200 but the content is not JSON
    WHEN is_ok is called
    THEN is_ok should be false
    WHEN load_detail is called
    THEN is should return a Detail object
    """
    resp = client.get(endpoint="/docs/static/logo.png", version=None)
    assert is_ok(resp) is False
    obj = load_detail(resp)
    obj.status_code = resp.status_code
    assert obj.status_code == 200
    assert isinstance(obj, Detail)
    assert str(obj).startswith("200:"), str(obj)


@pytest.mark.parametrize(
    "session_headers, extra_headers, expected_headers",
    [
        pytest.param(
            {"session-header": "value"},
            None,
            {"session-header": "value"},
            id="no-additional-headers",
        ),
        pytest.param(
            {"session-header": "value"},
            {"additional-header": "value"},
            {"session-header": "value", "additional-header": "value"},
            id="additional-headers",
        ),
        pytest.param(
            {"session-header": "value", "common-header": "session-value"},
            {"additional-header": "value", "common-header": "add-value"},
            {
                "session-header": "value",
                "additional-header": "value",
                "common-header": "add-value",
            },
            id="priority-additional-headers",
        ),
    ],
)
@patch("requests.Session.request")
@my_vcr.use_cassette
def test_extra_headers(
    request_mock: Mock,
    client: GGClient,
    session_headers: Any,
    extra_headers: Optional[Dict[str, str]],
    expected_headers: Dict[str, str],
):
    """
    GIVEN client's session headers
    WHEN calling any client method with additional headers
    THEN session/method headers should be merged with priority on method headers
    """
    client.session.headers = session_headers

    mock_response = Mock(spec=Response)
    mock_response.headers = {"content-type": "text"}
    mock_response.text = "some error"
    mock_response.status_code = 400
    request_mock.return_value = mock_response

    client.multi_content_scan(
        [{"filename": FILENAME, "document": DOCUMENT}],
        extra_headers=extra_headers,
    )
    assert request_mock.called
    _, kwargs = request_mock.call_args
    assert expected_headers == kwargs["headers"]

    client.content_scan("some_string", extra_headers=extra_headers)
    assert request_mock.called
    _, kwargs = request_mock.call_args
    assert expected_headers == kwargs["headers"]


def test_quota_overview(client: GGClient):
    with my_vcr.use_cassette("quota.yaml"):
        quota_response = client.quota_overview()
        assert type(repr(quota_response)) == str
        assert type(str(quota_response)) == str
        assert quota_response.status_code == 200
        if isinstance(quota_response, QuotaResponse):
            assert quota_response.content.limit == 5000
            assert quota_response.content.count == 2
            assert quota_response.content.remaining == 4998
            assert quota_response.content.since == date(2021, 4, 18)
        else:
            pytest.fail("returned should be a QuotaResponse")

        assert type(quota_response.to_dict()) == dict
        quota_response_json = quota_response.to_json()
        assert type(quota_response_json) == str
        assert type(json.loads(quota_response_json)) == dict
