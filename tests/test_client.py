import json
import re
import tarfile
from collections import OrderedDict
from datetime import date
from io import BytesIO
from typing import Any, Dict, List, Optional, Tuple, Type
from unittest.mock import Mock, patch

import pytest
import responses
from marshmallow import ValidationError
from responses import matchers

from pygitguardian import GGClient
from pygitguardian.client import GGClientCallbacks, is_ok, load_detail
from pygitguardian.config import (
    DEFAULT_BASE_URI,
    DEFAULT_PRE_COMMIT_MESSAGE,
    DEFAULT_PRE_PUSH_MESSAGE,
    DEFAULT_PRE_RECEIVE_MESSAGE,
    DOCUMENT_SIZE_THRESHOLD_BYTES,
    MULTI_DOCUMENT_LIMIT,
)
from pygitguardian.models import (
    AccessLevel,
    APITokensResponse,
    CreateInvitation,
    CreateInvitationParameters,
    CreateTeam,
    CreateTeamInvitation,
    CreateTeamMember,
    CreateTeamMemberParameters,
    DeleteMemberParameters,
    Detail,
    HoneytokenResponse,
    HoneytokenWithContextResponse,
    IncidentPermission,
    Invitation,
    JWTResponse,
    JWTService,
    Member,
    MembersParameters,
    MultiScanResult,
    QuotaResponse,
    ScanResult,
    Source,
    SourceParameters,
    Team,
    TeamInvitation,
    TeamInvitationParameters,
    TeamMember,
    TeamMemberParameters,
    TeamSourceParameters,
    TeamsParameters,
    UpdateMember,
    UpdateTeam,
    UpdateTeamSource,
)
from pygitguardian.models_utils import CursorPaginatedResponse

from .conftest import create_client, my_vcr
from .utils import get_source, get_team


FILENAME = ".env"
DOCUMENT = """
    import urllib.request
    url = 'http://jen_barber:correcthorsebatterystaple@cake.gitguardian.com/isreal.json'
    response = urllib.request.urlopen(url)
    consume(response.read())"
"""
EXAMPLE_RESPONSE = """
[{
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
    assert isinstance(multiscan, MultiScanResult)

    assert type(multiscan.to_dict()) == OrderedDict
    assert type(multiscan.to_json()) == str
    assert type(repr(multiscan)) == str
    assert type(str(multiscan)) == str
    assert multiscan.has_secrets == has_secrets
    assert multiscan.has_policy_breaks == has_policy_breaks

    if not expected:
        return

    example_dict = json.loads(expected)
    for i, scan_result in enumerate(multiscan.scan_results):
        assert all(elem in example_dict[i]["policies"] for elem in scan_result.policies)
        assert scan_result.policy_break_count == example_dict[i]["policy_break_count"]


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
            "secret",
            {"document": DOCUMENT},
            1,
            True,
            True,
            id="secret (deprecated)",
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
@pytest.mark.parametrize("all_secrets", (None, True, False))
def test_scan_parameters(client: GGClient, all_secrets):
    """
    GIVEN a ggclient
    WHEN calling content_scan with parameters
    THEN the parameters are passed in the request
    """

    to_match = {}
    if all_secrets is not None:
        to_match["all_secrets"] = all_secrets

    mock_response = responses.post(
        url=client._url_from_endpoint("scan", "v1"),
        status=200,
        match=[matchers.query_param_matcher(to_match)],
    )

    client.content_scan(
        DOCUMENT,
        FILENAME,
        all_secrets=all_secrets,
    )

    assert mock_response.call_count == 1


@responses.activate
@pytest.mark.parametrize("ignore_known_secrets", (None, True, False))
@pytest.mark.parametrize("all_secrets", (None, True, False))
def test_multiscan_parameters(client: GGClient, ignore_known_secrets, all_secrets):
    """
    GIVEN a ggclient
    WHEN calling multi_content_scan with parameters
    THEN the parameters are passed in the request
    """

    to_match = {}
    if ignore_known_secrets is not None:
        to_match["ignore_known_secrets"] = ignore_known_secrets
    if all_secrets is not None:
        to_match["all_secrets"] = all_secrets

    mock_response = responses.post(
        url=client._url_from_endpoint("multiscan", "v1"),
        status=200,
        match=[matchers.query_param_matcher(to_match)],
        json=[
            {
                "policy_break_count": 1,
                "policies": ["pol"],
                "policy_breaks": [
                    {
                        "type": "break",
                        "detector_name": "break",
                        "detector_group_name": "break",
                        "documentation_url": None,
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
        ignore_known_secrets=ignore_known_secrets,
        all_secrets=all_secrets,
    )

    assert mock_response.call_count == 1


@responses.activate
def test_retrieve_secret_incident(client: GGClient):
    """
    GIVEN a ggclient
    WHEN calling retrieve_secret_incident with parameters
    THEN the parameters are passed in the request
    """

    mock_response = responses.get(
        url=client._url_from_endpoint("incidents/secrets/3759", "v1"),
        status=200,
        match=[matchers.query_param_matcher({"with_occurrences": 20})],
        json={
            "id": 3759,
            "date": "2019-08-22T14:15:22Z",
            "detector": {
                "name": "slack_bot_token",
                "display_name": "Slack Bot Token",
                "nature": "specific",
                "family": "apikey",
                "detector_group_name": "slackbot_token",
                "detector_group_display_name": "Slack Bot Token",
            },
            "secret_hash": "Ri9FjVgdOlPnBmujoxP4XPJcbe82BhJXB/SAngijw/juCISuOMgPzYhV28m6OG24",
            "hmsl_hash": "05975add34ddc9a38a0fb57c7d3e676ffed57080516fc16bf8d8f14308fedb86",
            "gitguardian_url": "https://dashboard.gitguardian.com/workspace/1/incidents/3899",
            "regression": False,
            "status": "IGNORED",
            "assignee_id": 309,
            "assignee_email": "eric@gitguardian.com",
            "occurrences_count": 4,
            "secret_presence": {
                "files_requiring_code_fix": 1,
                "files_pending_merge": 1,
                "files_fixed": 1,
                "outside_vcs": 1,
                "removed_outside_vcs": 0,
                "in_vcs": 3,
                "removed_in_vcs": 0,
            },
            "ignore_reason": "test_credential",
            "triggered_at": "2019-05-12T09:37:49Z",
            "ignored_at": "2019-08-24T14:15:22Z",
            "ignorer_id": 309,
            "ignorer_api_token_id": "fdf075f9-1662-4cf1-9171-af50568158a8",
            "resolver_id": 395,
            "resolver_api_token_id": "fdf075f9-1662-4cf1-9171-af50568158a8",
            "secret_revoked": False,
            "severity": "high",
            "validity": "valid",
            "resolved_at": None,
            "share_url": "https://dashboard.gitguardian.com/share/incidents/11111111-1111-1111-1111-111111111111",
            "tags": ["FROM_HISTORICAL_SCAN", "SENSITIVE_FILE"],
            "feedback_list": [
                {
                    "created_at": "2021-05-20T12:40:55.662949Z",
                    "updated_at": "2021-05-20T12:40:55.662949Z",
                    "member_id": 42,
                    "email": "eric@gitguardian.com",
                    "answers": [
                        {
                            "type": "boolean",
                            "field_ref": "actual_secret_yes_no",
                            "field_label": "Is it an actual secret?",
                            "boolean": True,
                        }
                    ],
                }
            ],
            "occurrences": None,
        },
    )

    result = client.retrieve_secret_incident(3759)

    assert mock_response.call_count == 1
    assert result.id == 3759
    assert result.detector.name == "slack_bot_token"
    assert result.ignore_reason == "test_credential"
    assert result.secret_revoked is False


@responses.activate
def test_rate_limit():
    """
    GIVEN a GGClient instance with callbacks
    WHEN calling an API endpoint and we hit a rate-limit
    THEN the client retries after the delay
    AND the `on_rate_limited()` method of the callback is called
    """
    callbacks = Mock(spec=GGClientCallbacks)

    client = create_client(callbacks=callbacks)
    multiscan_url = client._url_from_endpoint("multiscan", "v1")

    rate_limit_response = responses.post(
        url=multiscan_url,
        status=429,
        headers={"Retry-After": "1"},
    )
    normal_response = responses.post(
        url=multiscan_url,
        status=200,
        json=[
            {
                "policy_break_count": 0,
                "policies": ["pol"],
                "policy_breaks": [],
            }
        ],
    )

    result = client.multi_content_scan(
        [{"filename": FILENAME, "document": DOCUMENT}],
    )

    assert rate_limit_response.call_count == 1
    assert normal_response.call_count == 1
    assert isinstance(result, MultiScanResult)
    callbacks.on_rate_limited.assert_called_once_with(1)


@responses.activate
def test_bogus_rate_limit():
    """
    GIVEN a GGClient instance with callbacks
    WHEN calling an API endpoint and we hit a rate-limit
    AND we can't parse the rate-limit value
    THEN the client just returns the error
    AND the `on_rate_limited()` method of the callback is not called
    """
    callbacks = Mock(spec=GGClientCallbacks)

    client = create_client(callbacks=callbacks)
    multiscan_url = client._url_from_endpoint("multiscan", "v1")

    rate_limit_response = responses.post(
        url=multiscan_url,
        status=429,
        headers={"Retry-After": "later"},
    )

    result = client.multi_content_scan(
        [{"filename": FILENAME, "document": DOCUMENT}],
    )

    assert rate_limit_response.call_count == 1
    assert isinstance(result, Detail)
    callbacks.on_rate_limited.assert_not_called()


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
@pytest.mark.parametrize("token", ["self", "token"])
def test_api_tokens(client: GGClient, token):
    """
    GIVEN a ggclient
    WHEN calling api_tokens with or without a token
    THEN the method returns the token details
    """
    mock_response = responses.get(
        url=client._url_from_endpoint(f"api_tokens/{token}", "v1"),
        content_type="application/json",
        status=201,
        json={
            "id": "5ddaad0c-5a0c-4674-beb5-1cd198d13360",
            "name": "myTokenName",
            "workspace_id": 42,
            "type": "personal_access_token",
            "status": "revoked",
            "created_at": "2023-05-20T12:40:55.662949Z",
            "last_used_at": "2023-05-24T12:40:55.662949Z",
            "expire_at": None,
            "revoked_at": "2023-05-27T12:40:55.662949Z",
            "member_id": 22015,
            "creator_id": 22015,
            "scopes": ["incidents:read", "scan"],
        },
    )

    result = client.api_tokens(token)

    assert mock_response.call_count == 1
    assert isinstance(result, APITokensResponse)


@responses.activate
def test_api_tokens_error(
    client: GGClient,
):
    """
    GIVEN a ggclient
    WHEN calling api_tokens with an invalid token
    THEN the method returns a Detail object containing the error detail
    """
    mock_response = responses.get(
        url=client._url_from_endpoint("api_tokens/invalid", "v1"),
        content_type="application/json",
        status=400,
        json={
            "detail": "Not authorized",
        },
    )

    result = client.api_tokens(token="invalid")

    assert mock_response.call_count == 1
    assert isinstance(result, Detail)


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
def test_create_honeytoken_with_context(
    client: GGClient,
):
    """
    GIVEN a ggclient
    WHEN calling create_honeytoken_with_context with parameters
    THEN the parameters are passed in the request
    AND the returned honeytoken use the parameters
    """
    mock_response = responses.post(
        url=client._url_from_endpoint("honeytokens/with-context", "v1"),
        content_type="application/json",
        status=201,
        json={
            "content": "def return_aws_credentials():\n \
                            aws_access_key_id = XXXXXXXX\n \
                            aws_secret_access_key = XXXXXXXX\n \
                            aws_region = us-west-2,\n \
                            return (aws_access_key_id, aws_secret_access_key, aws_region)\n",
            "filename": "aws.py",
            "language": "python",
            "suggested_commit_message": "Add AWS credentials",
            "honeytoken_id": "d45a123f-b15d-4fea-abf6-ff2a8479de5b",
            "gitguardian_url": "https://dashboard.gitguardian.com/workspace/1/honeytokens/d45a123f-b15d-4fea-abf6-ff2a8479de5b",  # noqa: E501
        },
    )

    result = client.create_honeytoken_with_context(
        name="honeytoken A",
        description="honeytoken used in the repository AA",
        type_="AWS",
        filename="aws.yaml",
    )

    assert mock_response.call_count == 1
    assert isinstance(result, HoneytokenWithContextResponse)


@responses.activate
def test_create_honeytoken_with_context_error(
    client: GGClient,
):
    """
    GIVEN a ggclient
    WHEN calling create_honeytoken_with_context with parameters without the right access
    THEN I get a Detail object containing the error detail
    """
    mock_response = responses.post(
        url=client._url_from_endpoint("honeytokens/with-context", "v1"),
        content_type="application/json",
        status=400,
        json={
            "detail": "Not authorized",
        },
    )

    result = client.create_honeytoken_with_context(
        name="honeytoken A",
        description="honeytoken used in the repository AA",
        type_="AWS",
        filename="aws.yaml",
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


def test_is_ok_bad_response():
    """
    GIVEN a 500 response with no content-type header
    WHEN is_ok() is called
    THEN it does not fail
    AND returns false
    """
    resp = Mock()
    resp.headers = {}
    resp.status_code = 500
    resp.text = "Failed"

    assert not is_ok(resp)


@responses.activate
def test_read_metadata_bad_response(client: GGClient):
    """
    GIVEN a /metadata endpoint that returns a 500 error with no content-type
    THEN a call to read_metadata() does not fail
    AND returns a valid Detail instance
    """
    mock_response = responses.get(
        url=client._url_from_endpoint("metadata", "v1"),
        status=500,
        body="Failed",
    )

    detail = client.read_metadata()

    assert mock_response.call_count == 1
    assert detail.status_code == 500
    assert detail.detail == "Failed"


METADATA_RESPONSE_NO_REMEDIATION_MESSAGES = {
    "version": "dev",
    "preferences": {
        "general__maximum_payload_size": 26214400,
    },
    "secret_scan_preferences": {
        "maximum_documents_per_scan": 20,
        "maximum_document_size": 1048576,
    },
}


@responses.activate
def test_read_metadata_no_remediation_message(client: GGClient):
    """
    GIVEN a /metadata endpoint that returns a 200 status code but no remediation message
    THEN a call to read_metadata() does not fail
    AND remediation_message are the default ones
    """
    mock_response = responses.get(
        url=client._url_from_endpoint("metadata", "v1"),
        body=json.dumps(METADATA_RESPONSE_NO_REMEDIATION_MESSAGES),
        content_type="application/json",
    )

    client.read_metadata()

    assert mock_response.call_count == 1
    assert client.remediation_messages.pre_commit == DEFAULT_PRE_COMMIT_MESSAGE
    assert client.remediation_messages.pre_push == DEFAULT_PRE_PUSH_MESSAGE
    assert client.remediation_messages.pre_receive == DEFAULT_PRE_RECEIVE_MESSAGE


@responses.activate
def test_read_metadata_remediation_message(client: GGClient):
    """
    GIVEN a /metadata endpoint that returns a 200 status code with a correct body with remediation message
    THEN a call to read_metadata() does not fail
    AND returns a valid Detail instance
    """
    messages = {
        "pre_commit": "message for pre-commit",
        "pre_push": "message for pre-push",
        "pre_receive": "message for pre-receive",
    }
    mock_response = responses.get(
        content_type="application/json",
        url=client._url_from_endpoint("metadata", "v1"),
        body=json.dumps(
            {
                **METADATA_RESPONSE_NO_REMEDIATION_MESSAGES,
                "remediation_messages": messages,
            }
        ),
    )

    client.read_metadata()

    assert mock_response.call_count == 1
    assert client.remediation_messages.pre_commit == messages["pre_commit"]
    assert client.remediation_messages.pre_push == messages["pre_push"]
    assert client.remediation_messages.pre_receive == messages["pre_receive"]


LIST_MEMBERS_RESPONSE = [
    {
        "id": 3251,
        "name": "Owl",
        "email": "john.smith@example.org",
        "role": "owner",
        "access_level": "owner",
        "active": True,
        "created_at": "2022-04-20T11:07:24.000Z",
        "last_login": "2022-04-20T11:07:24.000Z",
    },
    {
        "id": 3252,
        "name": "Owl",
        "email": "john.smith@example.org",
        "role": "owner",
        "access_level": "owner",
        "active": True,
        "created_at": "2022-04-20T11:07:24.000Z",
        "last_login": "2022-04-20T11:07:24.000Z",
    },
]


@my_vcr.use_cassette("test_list_members.yaml", ignore_localhost=False)
def test_list_members(client: GGClient):
    """
    GIVEN a client
    WHEN calling /members endpoint
    THEN it returns a paginated list of members
    """

    result = client.list_members()

    assert isinstance(result, CursorPaginatedResponse), result


@my_vcr.use_cassette("test_list_members_parameters.yaml", ignore_localhost=False)
def test_search_member(client: GGClient):
    """
    GIVEN a client
    WHEN calling /members endpoint
    AND parameters are passed
    THEN it returns a paginated list of members matching the parameters
    """

    result = client.list_members(MembersParameters(access_level=AccessLevel.MANAGER))

    assert isinstance(result, CursorPaginatedResponse), result
    assert all(member.access_level == AccessLevel.MANAGER for member in result.data)


@my_vcr.use_cassette("test_update_member.yaml", ignore_localhost=False)
def test_update_member(client: GGClient):
    """
    GIVEN a client
    WHEN calling PATCH /members/{id} endpoint with a payload
    THEN it returns the updated member
    """

    # This assumes there is at least one manager in the first page of members
    members = client.list_members(MembersParameters(access_level=AccessLevel.MANAGER))
    assert isinstance(members, CursorPaginatedResponse), "Could not fetch members"

    result = client.update_member(
        UpdateMember(
            id=members.data[0].id, access_level=AccessLevel.MEMBER, active=False
        )
    )

    assert isinstance(result, Member), result

    assert not result.active
    assert result.access_level == AccessLevel.MEMBER


@my_vcr.use_cassette("test_delete_member.yaml", ignore_localhost=False)
def test_delete_member(client: GGClient):
    """
    GIVEN a client
    WHEN calling DELETE /members/{id} endpoint
    THEN the member is deleted
    """

    members = client.list_members(MembersParameters(access_level=AccessLevel.MEMBER))
    assert isinstance(members, CursorPaginatedResponse), "Could not fetch members"

    member = members.data[0]
    result = client.delete_member(DeleteMemberParameters(id=member.id))

    assert result is None, result


@my_vcr.use_cassette("test_create_team.yaml", ignore_localhost=False)
def test_create_team(client: GGClient):
    """
    GIVEN a client
    WHEN calling POST /teams endpoint
    THEN a team is created
    """

    result = client.create_team(CreateTeam(name="PyGitGuardian team"))

    assert isinstance(result, Team), result


@my_vcr.use_cassette("test_get_team.yaml", ignore_localhost=False)
def test_get_team(client: GGClient):
    """
    GIVEN a client
    WHEN calling GET /teams/{id} endpoint
    THEN the corresponding team is returned
    """

    # This test would require a team to be created first and its id
    # stored in a config file for this test to simulate a real use case
    team = get_team()
    result = client.get_team(team.id)

    assert isinstance(result, Team), result


@my_vcr.use_cassette("test_update_team.yaml", ignore_localhost=False)
def test_update_team(client: GGClient):
    """
    GIVEN a client
    WHEN calling PATCH /teams endpoint
    THEN the corresponding team is updated
    """

    team = get_team()
    result = client.update_team(
        UpdateTeam(
            id=team.id, name="New PyGitGuardian team", description="New description"
        )
    )

    assert isinstance(result, Team), result

    assert result.name == "New PyGitGuardian team"
    assert result.description == "New description"


@my_vcr.use_cassette("test_list_teams.yaml", ignore_localhost=False)
def test_list_teams(client: GGClient):
    """
    GIVEN a client
    WHEN calling GET /teams endpoint
    THEN a paginated list of teams is returned
    """

    result = client.list_teams()

    assert isinstance(result, CursorPaginatedResponse), result
    assert isinstance(result.data[0], Team)


@my_vcr.use_cassette("test_global_team.yaml", ignore_localhost=False)
def test_global_team(client: GGClient):
    """
    GIVEN a client
    WHEN calling GET /teams endpoint
    AND passing is_global parameter
    THEN the global team is returned
    """

    result = client.list_teams(parameters=TeamsParameters(is_global=True))

    assert isinstance(result, CursorPaginatedResponse), result

    assert all(team.is_global for team in result.data)


@my_vcr.use_cassette("test_delete_team.yaml", ignore_localhost=False)
def test_delete_team(client: GGClient):
    """
    GIVEN a client
    WHEN calling DELETE /teams/{id} endpoint
    THEN the team is deleted
    """

    team = get_team()
    result = client.delete_team(team.id)

    assert result is None


@my_vcr.use_cassette("test_create_team_invitation.yaml", ignore_localhost=False)
def test_create_team_invitation(client: GGClient):
    """
    GIVEN a client
    WHEN calling POST /teams/{id}/invitations endpoint
    THEN an invitation is created
    """

    team = get_team()
    invitation = client.create_invitation(
        CreateInvitation(
            "pygitguardian+create_team_invitation@example.com", AccessLevel.MEMBER
        )
    )

    assert isinstance(invitation, Invitation), invitation.detail

    result = client.create_team_invitation(
        team.id,
        CreateTeamInvitation(
            invitation_id=invitation.id,
            is_team_leader=True,
            incident_permission=IncidentPermission.VIEW,
        ),
    )

    assert isinstance(result, TeamInvitation), result


@my_vcr.use_cassette("test_list_team_invitations.yaml", ignore_localhost=False)
def test_list_team_invitations(client: GGClient):
    """
    GIVEN a client
    WHEN calling GET /teams/{id}/invitations endpoint
    THEN a paginated list of invitations is returned
    """

    team = get_team()
    result = client.list_team_invitations(team.id)

    assert isinstance(result, CursorPaginatedResponse), result
    # This assumes there is at least one team invitation
    assert isinstance(result.data[0], TeamInvitation)


@my_vcr.use_cassette("test_search_team_invitations.yaml", ignore_localhost=False)
def test_search_team_invitations(client: GGClient):
    """
    GIVEN a client
    WHEN calling GET /teams/{id}/invitations endpoint
    AND parameters are passed
    THEN a paginated list of invitations is returned matching the parameters
    """

    team = get_team()
    result = client.list_team_invitations(
        team.id,
        parameters=TeamInvitationParameters(
            incident_permission=IncidentPermission.VIEW
        ),
    )

    assert isinstance(result, CursorPaginatedResponse), result
    assert all(
        invitation.incident_permission == "can_view" for invitation in result.data
    )


@my_vcr.use_cassette("test_delete_team_invitation.yaml", ignore_localhost=False)
def test_delete_team_invitation(client: GGClient):
    """
    GIVEN a client
    WHEN calling DELETE /teams/{id}/invitations/{id} endpoint
    THEN an invitation is deleted
    """

    team = get_team()
    team_invitations = client.list_team_invitations(team.id)
    assert isinstance(
        team_invitations, CursorPaginatedResponse
    ), "Could not fetch team invitations"

    result = client.delete_team_invitation(team.id, team_invitations.data[0].id)

    assert result is None


@my_vcr.use_cassette("test_list_team_members.yaml", ignore_localhost=False)
def test_list_team_members(client: GGClient):
    """
    GIVEN a client
    WHEN calling GET /teams/{id}/members endpoint
    THEN a paginated list of members is returned
    """

    team = get_team()
    result = client.list_team_members(team.id)

    assert isinstance(result, CursorPaginatedResponse), result
    assert isinstance(result.data[0], TeamMember)


@my_vcr.use_cassette("test_search_team_members.yaml", ignore_localhost=False)
def test_search_team_members(client: GGClient):
    """
    GIVEN a client
    WHEN calling GET /teams/{id}/members endpoint
    AND parameters are passed
    THEN a paginated list of members is returned matching the parameters
    """

    team = get_team()

    # Every team should have at least one team leader, but an account without a team
    # will nullify the purpose of this test even though it will pass
    result = client.list_team_members(
        team.id, parameters=TeamMemberParameters(is_team_leader=True)
    )

    assert isinstance(result, CursorPaginatedResponse), result
    assert all(member.is_team_leader for member in result.data)


@my_vcr.use_cassette("test_create_team_member.yaml", ignore_localhost=False)
def test_create_team_member(client: GGClient):
    """
    GIVEN a client
    WHEN calling POST /teams/{id}/members endpoint
    THEN a member is created
    """

    all_members = client.list_members()
    assert isinstance(
        all_members, CursorPaginatedResponse
    ), "Could not fetch members from GitGuardian"

    team = get_team()
    team_members = client.list_team_members(team.id)
    assert isinstance(
        team_members, CursorPaginatedResponse
    ), "Could not fetch team members from GitGuardian"
    team_members_ids = {team_member.member_id for team_member in team_members.data}

    # This assumes there is at least one member in the first page of team members that
    # does not belong to the retrieved team
    member_to_add = next(
        member for member in all_members.data if member.id not in team_members_ids
    )

    result = client.create_team_member(
        team.id,
        CreateTeamMember(member_to_add.id, False, IncidentPermission.FULL_ACCESS),
    )

    assert isinstance(result, TeamMember), result

    assert result.incident_permission == IncidentPermission.FULL_ACCESS


@my_vcr.use_cassette("test_create_team_member_parameters.yaml", ignore_localhost=False)
def test_create_team_member_without_mail(client: GGClient):
    """
    GIVEN a client
    WHEN calling POST /teams/{id}/members endpoint
    THEN a member is created
    """

    all_members = client.list_members()
    assert isinstance(
        all_members, CursorPaginatedResponse
    ), "Could not fetch members from GitGuardian"

    team = get_team()
    team_members = client.list_team_members(team.id)
    assert isinstance(
        team_members, CursorPaginatedResponse
    ), "Could not fetch team members from GitGuardian"
    team_members_ids = {team_member.member_id for team_member in team_members.data}

    # This assumes there is at least one member in the first page of team members that
    # does not belong to the retrieved team
    member_to_add = next(
        member for member in all_members.data if member.id not in team_members_ids
    )

    result = client.create_team_member(
        team.id,
        CreateTeamMember(member_to_add.id, False, IncidentPermission.FULL_ACCESS),
        CreateTeamMemberParameters(send_email=False),
    )

    assert isinstance(result, TeamMember), result


@my_vcr.use_cassette("test_delete_team_member.yaml", ignore_localhost=False)
def test_delete_team_member(client: GGClient):
    """
    GIVEN a client
    WHEN calling DELETE /teams/{id}/members/{id} endpoint
    THEN a member is deleted
    """

    all_members = client.list_members()
    assert isinstance(
        all_members, CursorPaginatedResponse
    ), "Could not fetch members from GitGuardian"

    team = get_team()
    team_members = client.list_team_members(
        team.id, TeamMemberParameters(is_team_leader=False)
    )
    assert isinstance(
        team_members, CursorPaginatedResponse
    ), "Could not fetch team members from GitGuardian"

    team_member = team_members.data[0]
    result = client.delete_team_member(team.id, team_member.id)

    assert result is None


@my_vcr.use_cassette("test_list_sources.yaml", ignore_localhost=False)
def test_list_sources(client: GGClient):
    """
    GIVEN a client
    WHEN calling GET /sources endpoint
    THEN a paginated list of sources is returned
    """

    result = client.list_sources()
    assert isinstance(result, CursorPaginatedResponse), result
    assert isinstance(result.data[0], Source)


@my_vcr.use_cassette("test_search_sources.yaml", ignore_localhost=False)
def test_search_sources(client: GGClient):
    """
    GIVEN a client
    WHEN calling GET /sources endpoint
    AND parameters are passed
    THEN a paginated list of sources is returned matching the parameters
    """

    result = client.list_sources(parameters=SourceParameters(type="azure_devops"))

    assert isinstance(result, CursorPaginatedResponse), result
    assert all(source.type == "azure_devops" for source in result.data)


@my_vcr.use_cassette("test_list_teams_sources.yaml", ignore_localhost=False)
def test_list_team_sources(client: GGClient):
    """
    GIVEN a client
    WHEN calling GET /sources endpoint
    THEN a paginated list of sources is returned
    """

    result = client.list_team_sources(get_team().id)
    assert isinstance(result, CursorPaginatedResponse), result

    # This assumes at least one source has been installed and is on the perimeter of a team
    assert isinstance(result.data[0], Source)


@my_vcr.use_cassette("test_search_teams_sources.yaml", ignore_localhost=False)
def test_search_team_sources(client: GGClient):
    """
    GIVEN a client
    WHEN calling GET /sources endpoint
    AND parameters are passed
    THEN a paginated list of sources is returned matching the parameters
    """

    result = client.list_team_sources(
        get_team().id, TeamSourceParameters(type="azure_devops")
    )

    assert isinstance(result, CursorPaginatedResponse), result
    assert all(source.type == "azure_devops" for source in result.data)


@my_vcr.use_cassette("test_delete_team_sources.yaml", ignore_localhost=False)
def test_delete_team_sources(client: GGClient):
    """
    GIVEN a client
    WHEN calling POST /teams/{id}/sources endpoint
    THEN a source is deleted
    """

    team = get_team()
    team_sources = client.list_team_sources(team.id)
    assert isinstance(
        team_sources, CursorPaginatedResponse
    ), "Could not fetch team sources"
    source_to_delete = team_sources.data[0]
    result = client.update_team_source(
        UpdateTeamSource(team.id, [], [source_to_delete.id])
    )

    assert result is None

    team_sources = client.list_team_sources(team.id)
    assert isinstance(team_sources, CursorPaginatedResponse), team_sources
    assert not any(source.id == source_to_delete.id for source in team_sources.data)


@my_vcr.use_cassette("test_add_team_sources.yaml", ignore_localhost=False)
def test_add_team_sources(client: GGClient):
    """
    GIVEN a client
    WHEN calling POST /teams/{id}/sources endpoint
    THEN a source is added
    """

    team = get_team()
    source = get_source()

    result = client.update_team_source(
        UpdateTeamSource(team.id, [source.id], []),
    )

    assert result is None

    team_sources = client.list_team_sources(
        team.id, TeamSourceParameters(type="azure_devops")
    )
    assert isinstance(team_sources, CursorPaginatedResponse), team_sources
    assert any(received_source.id == source.id for received_source in team_sources.data)


@my_vcr.use_cassette("test_list_invitations.yaml", ignore_localhost=False)
def test_list_invitations(client: GGClient):
    """
    GIVEN a client
    WHEN calling GET /invitations endpoint
    THEN a paginated list of invitations is returned
    """

    result = client.list_invitations()
    assert isinstance(result, CursorPaginatedResponse), result
    # This assumes there is at least one invitation sent in the account
    assert isinstance(result.data[0], Invitation)


@my_vcr.use_cassette("test_send_invitation.yaml", ignore_localhost=False)
def test_send_invitation(client: GGClient):
    """
    GIVEN a client
    WHEN calling POST /invitations endpoint
    THEN an invitation is sent
    """

    result = client.create_invitation(
        CreateInvitation(
            email="pygitguardian@example.com", access_level=AccessLevel.MEMBER
        ),
        CreateInvitationParameters(send_email=False),
    )

    assert isinstance(result, Invitation), result

    assert result.email == "pygitguardian@example.com"
    assert result.access_level == AccessLevel.MEMBER


@my_vcr.use_cassette("test_delete_invitation.yaml", ignore_localhost=False)
def test_delete_invitation(client: GGClient):
    """
    GIVEN a client
    WHEN calling DELETE /invitations/{id} endpoint
    THEN the invitation is deleted
    """

    invitations = client.list_invitations()
    assert isinstance(
        invitations, CursorPaginatedResponse
    ), "Could not fetch invitations"

    result = client.delete_invitation(invitations.data[0].id)

    assert result is None
