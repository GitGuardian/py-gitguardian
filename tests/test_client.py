import json
import re
import tarfile
from collections import OrderedDict
from datetime import date
from io import BytesIO
from typing import Any, Dict, List, Optional, Tuple, Type
from unittest.mock import patch

import pytest
import responses
from marshmallow import ValidationError
from responses import matchers

from pygitguardian import GGClient
from pygitguardian.client import is_ok, load_detail
from pygitguardian.config import (
    DEFAULT_BASE_URI,
    DOCUMENT_SIZE_THRESHOLD_BYTES,
    MULTI_DOCUMENT_LIMIT,
)
from pygitguardian.models import (
    Detail,
    HoneytokenResponse,
    JWTResponse,
    JWTService,
    MultiScanResult,
    QuotaResponse,
    ScanResult,
)
from pygitguardian.sca_models import (
    ComputeSCAFilesResult,
    SCAScanAllOutput,
    SCAScanDiffOutput,
    SCAScanParameters,
)

from .conftest import my_vcr


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
        pytest.param(
            "–––––––FILL-ME–––––––––",
            "https://api.gitguardian.com/",
            "None",
            30.0,
            ValueError,
            id="U+2013 dash characters in API key",
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
        assert client.session.headers["Authorization"] == f"Token {api_key}"


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
            ), f"Could not get the expected URL for base_uri=`{curr_base_uri}`"


@my_vcr.use_cassette
def test_health_check(client: GGClient):
    health = client.health_check()
    assert health.status_code == 200
    assert health.detail == "Valid API key."
    assert re.match(r"^v\d+\.\d+\.\d+([-0-9.rc])?$", health.app_version)
    assert re.match(r"^\d+\.\d+\.\d+$", health.secrets_engine_version)
    assert bool(health)
    assert health.success

    assert type(health.to_dict()) == OrderedDict
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

        assert type(multiscan.to_dict()) == OrderedDict
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
    client = GGClient(api_key="invalid")

    obj = client.multi_content_scan(req)

    assert obj.status_code == 401
    assert isinstance(obj, Detail)
    assert obj.detail == "Invalid API key."


@my_vcr.use_cassette
def test_content_not_ok():
    req = {"document": "valid", "filename": "valid"}
    client = GGClient(api_key="invalid")

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
        pytest.param(
            "secret", {"document": DOCUMENT}, 1, True, True, id="secret (deprecated)"
        ),
        pytest.param(
            "secret_validity",
            {"document": DOCUMENT},
            1,
            True,
            True,
            id="secret with validity",
        ),
        pytest.param(
            "document_with_0_bytes",
            {"document": "Hello\0World"},
            0,
            False,
            False,
            id="Document containing a 0 byte",
        ),
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

        assert type(scan_result.to_dict()) == OrderedDict
        scan_result_json = scan_result.to_json()
        assert type(scan_result_json) == str
        assert type(json.loads(scan_result_json)) == dict


@my_vcr.use_cassette
def test_assert_content_type():
    """
    GIVEN a response that's 200 but the content is not JSON
    WHEN is_ok is called
    THEN is_ok should be false
    WHEN load_detail is called
    THEN it should return a Detail object
    """
    client = GGClient(api_key="", base_uri="https://docs.gitguardian.com")
    resp = client.get(endpoint="/img/gg_owl.svg", version=None)
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
@responses.activate
def test_extra_headers(
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

    mock_response = responses.post(
        url=client._url_from_endpoint("multiscan", "v1"),
        content_type="text/plain",
        body="some error",
        status=400,
        match=[matchers.header_matcher(extra_headers)] if extra_headers else [],
    )

    client.multi_content_scan(
        [{"filename": FILENAME, "document": DOCUMENT}],
        extra_headers=extra_headers,
    )
    assert mock_response.call_count == 1

    # Same test for content_scan
    mock_response = responses.post(
        url=client._url_from_endpoint("scan", "v1"),
        content_type="text/plain",
        body="some error",
        status=400,
        match=[matchers.header_matcher(extra_headers)] if extra_headers else [],
    )
    client.content_scan("some_string", extra_headers=extra_headers)
    assert mock_response.call_count == 1


@responses.activate
def test_multiscan_parameters(
    client: GGClient,
):
    """
    GIVEN a ggclient
    WHEN calling multi_content_scan with parameters
    THEN the parameters are passed in the request
    """

    mock_response = responses.post(
        url=client._url_from_endpoint("multiscan", "v1"),
        status=200,
        match=[matchers.query_param_matcher({"ignore_known_secrets": True})],
        json=[
            {
                "policy_break_count": 1,
                "policies": ["pol"],
                "policy_breaks": [
                    {
                        "type": "break",
                        "policy": "mypol",
                        "matches": [
                            {
                                "match": "hello",
                                "type": "hello",
                            }
                        ],
                    }
                ],
            }
        ],
    )

    client.multi_content_scan(
        [{"filename": FILENAME, "document": DOCUMENT}],
        ignore_known_secrets=True,
    )

    assert mock_response.call_count == 1


def test_quota_overview(client: GGClient):
    with my_vcr.use_cassette("quota.yaml"):
        quota_response = client.quota_overview()
        assert type(repr(quota_response)) == str
        assert type(str(quota_response)) == str
        assert quota_response.status_code == 200
        if isinstance(quota_response, QuotaResponse):
            content = quota_response.content
            assert content.count + content.remaining == content.limit
            assert content.limit > 0
            assert 2021 <= content.since.year <= date.today().year
        else:
            pytest.fail("returned should be a QuotaResponse")

        assert type(quota_response.to_dict()) == OrderedDict
        quota_response_json = quota_response.to_json()
        assert type(quota_response_json) == str
        assert type(json.loads(quota_response_json)) == dict


@pytest.mark.parametrize("method", ["GET", "POST"])
@responses.activate
def test_versions_from_headers(client: GGClient, method):
    """
    GIVEN a GGClient instance
    WHEN an HTTP request to GitGuardian API is made
    THEN the app_version and secrets_engine_version fields are set from the headers of
         the HTTP response
    """
    url = client._url_from_endpoint("endpoint", "v1")
    app_version_value = "1.0"
    secrets_engine_version_value = "2.0"

    mock_response = responses.add(
        method=method,
        url=url,
        headers={
            "X-App-Version": app_version_value,
            "X-Secrets-Engine-Version": secrets_engine_version_value,
        },
    )

    client.request(method=method, endpoint="endpoint")
    assert mock_response.call_count == 1

    assert client.app_version == app_version_value
    assert client.secrets_engine_version == secrets_engine_version_value

    # WHEN making another HTTP call whose response headers does not contain the version
    # fields
    # THEN known version fields remain set
    mock_response = responses.add(method=method, url=url)
    client.request(method=method, endpoint="endpoint")
    assert mock_response.call_count == 1

    assert client.app_version == app_version_value
    assert client.secrets_engine_version == secrets_engine_version_value

    # WHEN creating another GGClient instance
    # THEN it already has the fields set
    other_client = GGClient(api_key="")
    assert other_client.app_version == app_version_value
    assert other_client.secrets_engine_version == secrets_engine_version_value


@responses.activate
def test_create_honeytoken(
    client: GGClient,
):
    """
    GIVEN a ggclient
    WHEN calling create_honeytoken with parameters
    THEN the parameters are passed in the request
    AND the returned honeytoken use the parameters
    """
    mock_response = responses.post(
        url=client._url_from_endpoint("honeytokens", "v1"),
        content_type="application/json",
        status=201,
        json={
            "id": "d45a123f-b15d-4fea-abf6-ff2a8479de5b",
            "name": "honeytoken A",
            "description": "honeytoken used in the repository AA",
            "created_at": "2019-08-22T14:15:22Z",
            "gitguardian_url": "https://dashboard.gitguardian.com/workspace/1/honeytokens/d45a123f-b15d-4fea-abf6-ff2a8479de5b",  # noqa: E501
            "status": "active",
            "triggered_at": "2019-08-22T14:15:22Z",
            "revoked_at": None,
            "open_events_count": 2,
            "type": "AWS",
            "creator_id": 122,
            "revoker_id": None,
            "creator_api_token_id": None,
            "revoker_api_token_id": None,
            "token": {"access_token_id": "AAAA", "secret_key": "BBB"},
            "tags": ["publicly_exposed"],
        },
    )

    result = client.create_honeytoken(
        name="honeytoken A",
        description="honeytoken used in the repository AA",
        type_="AWS",
    )

    assert mock_response.call_count == 1
    assert isinstance(result, HoneytokenResponse)


@responses.activate
def test_create_honeytoken_error(
    client: GGClient,
):
    """
    GIVEN a ggclient
    WHEN calling create_honeytoken with parameters without the right access
    THEN I get a Detail object containing the error detail
    """
    mock_response = responses.post(
        url=client._url_from_endpoint("honeytokens", "v1"),
        content_type="application/json",
        status=400,
        json={
            "detail": "Not authorized",
        },
    )

    result = client.create_honeytoken(
        name="honeytoken A",
        description="honeytoken used in the repository AA",
        type_="AWS",
    )

    assert mock_response.call_count == 1
    assert isinstance(result, Detail)


@responses.activate
def test_create_jwt(
    client: GGClient,
):
    """
    GIVEN a ggclient
    WHEN calling create_jwt
    THEN we receive a token
    """
    mock_response = responses.post(
        url=client._url_from_endpoint("auth/jwt", "v1"),
        match=[
            matchers.json_params_matcher(
                {
                    "audience": "dummy_audience",
                    "audience_type": "hmsl",
                }
            )
        ],
        content_type="application/json",
        status=200,
        json={"token": "dummy_token"},
    )

    result = client.create_jwt("dummy_audience", JWTService.HMSL)

    assert mock_response.call_count == 1
    assert isinstance(result, JWTResponse)
    assert result.token == "dummy_token"


def make_tar_bytes(files: List[Tuple[str, str]]) -> bytes:
    """
    util to generate tars in client tests
    """
    buffer = BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar_file:
        for name, content in files:
            raw_content = content.encode()
            info = tarfile.TarInfo(name=name)
            info.size = len(raw_content)
            tar_file.addfile(info, BytesIO(raw_content))
    buffer.seek(0)
    return buffer.getvalue()


reference_files = [
    (
        "Pipfile.lock",
        """
        {
            "default": {
                "foo": {
                    "version": "==1.2.3"
                },
                "bar": {
                    "version": "==3.4.5"
                }
            }
        }
        """,
    ),
]
current_files = [
    (
        "Pipfile",
        "# This Pipfile is empty",
    ),
    (
        "Pipfile.lock",
        # With a vulnerable package
        """
        {
            "default": {
                "foo": {
                    "version": "==1.2.4"
                },
                "vyper": {
                    "version": "==0.2.10"
                }
            }
        }
        """,
    ),
]


@my_vcr.use_cassette("test_sca_scan_compute_files.yaml", ignore_localhost=False)
def test_compute_sca_files(client: GGClient):
    result = client.compute_sca_files(files=["Pipfile", "something_else"])
    assert isinstance(result, ComputeSCAFilesResult)
    assert result.sca_files == ["Pipfile"]
    assert result.potential_siblings == ["Pipfile.lock"]


@my_vcr.use_cassette("test_sca_scan_directory_valid.yaml", ignore_localhost=False)
def test_sca_scan_directory(client: GGClient):
    """
    GIVEN a directory with a Pipfile.lock containing vulnerabilities
    WHEN calling sca_scan_directory on this directory
    THEN we get the expected vulnerabilities
    """

    scan_params = SCAScanParameters()

    response = client.sca_scan_directory(make_tar_bytes(current_files), scan_params)
    assert isinstance(response, SCAScanAllOutput)
    assert response.status_code == 200
    assert len(response.scanned_files) == 2
    vuln_pkg = next(
        (
            package_vuln
            for package_vuln in response.found_package_vulns[0].package_vulns
            if package_vuln.package_full_name == "vyper"
        ),
        None,
    )
    assert vuln_pkg is not None
    assert len(vuln_pkg.vulns) == 13


@my_vcr.use_cassette("test_sca_scan_directory_invalid_tar.yaml", ignore_localhost=False)
def test_sca_scan_directory_invalid_tar(client: GGClient):
    """
    GIVEN an invalid tar argument
    WHEN calling sca_scan_directory
    THEN we get a 400 status code
    """
    tar = ""
    scan_params = SCAScanParameters()

    response = client.sca_scan_directory(tar, scan_params)
    assert isinstance(response, Detail)
    assert response.status_code == 400


@my_vcr.use_cassette("test_sca_client_scan_diff.yaml", ignore_localhost=False)
def test_sca_client_scan_diff(client: GGClient):
    """
    GIVEN a directory in two different states
    WHEN calling scan_diff on it
    THEN the scan succeeds
    """
    scan_params = SCAScanParameters()

    result = client.scan_diff(
        reference=make_tar_bytes(reference_files),
        current=make_tar_bytes(current_files),
        scan_parameters=scan_params,
    )
    assert isinstance(result, SCAScanDiffOutput), result.content
    assert result.scanned_files == ["Pipfile", "Pipfile.lock"]
