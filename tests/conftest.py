import os
from copy import deepcopy
from os.path import dirname, join, realpath
from typing import Any, Dict

import pytest
import vcr

from pygitguardian import GGClient


my_vcr = vcr.VCR(
    cassette_library_dir=join(dirname(realpath(__file__)), "cassettes"),
    path_transformer=vcr.VCR.ensure_suffix(".yaml"),
    decode_compressed_response=True,
    ignore_localhost=True,
    match_on=["method", "url"],
    serializer="yaml",
    record_mode="once",
    filter_headers=["Authorization"],
)


def create_client(**kwargs: Any) -> GGClient:
    """Create a GGClient using $GITGUARDIAN_API_KEY"""
    api_key = os.environ["GITGUARDIAN_API_KEY"]
    return GGClient(api_key=api_key, **kwargs)


@pytest.fixture
def client():
    return create_client()


_SECRET_INCIDENT = {
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
    "custom_tags": [
        {
            "id": "9df8c1c9-7367-4c77-a0f0-9f2d4b22bdda",
            "key": "commiter",
            "value": "leaky mcgee",
        },
        {
            "id": "1aa3ae34-f9f0-42e1-a687-9fed877a9037",
            "key": "confrence",
            "value": "grrcon",
        },
        {
            "id": "2cade8a1-71ff-46d2-bbe3-c2bf71437ae7",
            "key": "confrence test",
            "value": "hacktivity",
        },
        {
            "id": "3dade8a1-71ff-46d2-bbe3-c2bf71437ae8",
            "key": "no value",
            "value": None,
        },
    ],
}


def create_secret_incident_payload(**overrides: Any) -> Dict[str, Any]:
    """Build the JSON body of GET /v1/incidents/secrets/<id>, with fields overridden."""
    return {**deepcopy(_SECRET_INCIDENT), **overrides}
