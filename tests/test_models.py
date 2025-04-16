from typing import OrderedDict

import pytest

from pygitguardian.models import (
    APITokensResponse,
    APITokensResponseSchema,
    Detail,
    DetailSchema,
    Document,
    DocumentSchema,
    HealthCheckResponseSchema,
    HoneytokenResponse,
    HoneytokenResponseSchema,
    HoneytokenWithContextResponse,
    HoneytokenWithContextResponseSchema,
    Match,
    MatchSchema,
    MultiScanResult,
    MultiScanResultSchema,
    PolicyBreak,
    PolicyBreakSchema,
    Quota,
    QuotaResponse,
    QuotaResponseSchema,
    QuotaSchema,
    ScanResult,
    ScanResultSchema,
    SecretIncident,
    SecretIncidentSchema,
    SecretOccurrence,
    SecretOccurrenceSchema,
)


class TestModel:
    def test_document_model(self):
        """
        GIVEN a simple document
        THEN base model methods should produce the appropriate types.
        """
        document = Document("hello", "hello")
        assert isinstance(document.to_json(), str)
        assert isinstance(document.to_dict(), dict)
        assert isinstance(str(document), str)

    def test_document_handle_0_bytes(self):
        document = Document.SCHEMA.load(
            {"filename": "name", "document": "hello\0world"}
        )
        assert document["document"] == "hello\x1aworld"

    def test_document_handle_surrogates(self):
        document = Document.SCHEMA.load(
            {"filename": "name", "document": "hello\udbdeworld"}
        )
        assert document["document"] == "hello?world", document

    @pytest.mark.parametrize(
        "schema_klass, expected_klass, instance_data",
        [
            (DocumentSchema, OrderedDict, {"filename": "hello", "document": "hello"}),
            (
                HealthCheckResponseSchema,
                OrderedDict,
                {"detail": "hello", "status_code": 200},
            ),
            (
                APITokensResponseSchema,
                APITokensResponse,
                {
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
            ),
            (MatchSchema, Match, {"match": "hello", "type": "hello"}),
            (
                MultiScanResultSchema,
                MultiScanResult,
                {
                    "scan_results": [
                        {
                            "policy_break_count": 1,
                            "policies": ["pol"],
                            "policy_breaks": [
                                {
                                    "type": "break",
                                    "detector_name": "hello",
                                    "detector_group_name": "hello",
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
                    "type": "hello",
                },
            ),
            (
                PolicyBreakSchema,
                PolicyBreak,
                {
                    "type": "hello",
                    "detector_name": "hello",
                    "detector_group_name": "hello",
                    "documentation_url": None,
                    "policy": "hello",
                    "validity": "hey",
                    "matches": [{"match": "hello", "type": "hello"}],
                },
            ),
            (
                PolicyBreakSchema,
                PolicyBreak,
                {
                    "type": "hello",
                    "detector_name": "hello",
                    "detector_group_name": "hello",
                    "documentation_url": None,
                    "policy": "hello",
                    "validity": "hey",
                    "known_secret": True,
                    "incident_url": "https://api.gitguardian.com/workspace/2/incidents/3",
                    "matches": [{"match": "hello", "type": "hello"}],
                },
            ),
            (
                PolicyBreakSchema,
                PolicyBreak,
                {
                    "type": "hello",
                    "detector_name": "hello",
                    "detector_group_name": "hello",
                    "documentation_url": None,
                    "policy": "hello",
                    "validity": "hey",
                    "known_secret": True,
                    "incident_url": "https://api.gitguardian.com/workspace/2/incidents/3",
                    "matches": [{"match": "hello", "type": "hello"}],
                    "is_excluded": True,
                    "exclude_reason": "bad secret",
                },
            ),
            (
                PolicyBreakSchema,
                PolicyBreak,
                {
                    "type": "hello",
                    "detector_name": "hello",
                    "detector_group_name": "hello",
                    "documentation_url": None,
                    "policy": "hello",
                    "validity": "hey",
                    "known_secret": True,
                    "incident_url": "https://api.gitguardian.com/workspace/2/incidents/3",
                    "matches": [{"match": "hello", "type": "hello"}],
                    "is_excluded": False,
                    "exclude_reason": None,
                    "diff_kind": None,
                },
            ),
            (
                PolicyBreakSchema,
                PolicyBreak,
                {
                    "type": "hello",
                    "detector_name": "hello",
                    "detector_group_name": "hello",
                    "documentation_url": None,
                    "policy": "hello",
                    "validity": "hey",
                    "known_secret": True,
                    "incident_url": "https://api.gitguardian.com/workspace/2/incidents/3",
                    "matches": [{"match": "hello", "type": "hello"}],
                    "is_excluded": False,
                    "exclude_reason": None,
                    "diff_kind": "addition",
                },
            ),
            (
                QuotaSchema,
                Quota,
                {
                    "count": 1,
                    "limit": 1,
                    "remaining": 1,
                    "since": "2021-04-18",
                },
            ),
            (
                QuotaResponseSchema,
                QuotaResponse,
                {
                    "content": {
                        "count": 1,
                        "limit": 1,
                        "remaining": 1,
                        "since": "2021-04-18",
                    }
                },
            ),
            (
                ScanResultSchema,
                ScanResult,
                {"policy_break_count": 1, "policy_breaks": [], "policies": []},
            ),
            (
                ScanResultSchema,
                ScanResult,
                {
                    "policy_break_count": 1,
                    "policy_breaks": [],
                    "policies": [],
                    "is_diff": True,
                },
            ),
            (
                DetailSchema,
                Detail,
                {"detail": "Fail"},
            ),
            (
                HoneytokenResponseSchema,
                HoneytokenResponse,
                {
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
            ),
            (
                HoneytokenWithContextResponseSchema,
                HoneytokenWithContextResponse,
                {
                    "content": "def return_aws_credentials():\n \
                                    aws_access_key_id = XXXXXXXX\n \
                                    aws_secret_access_key = XXXXXXXX\n \
                                    aws_region = us-west-2\n \
                                    return (aws_access_key_id, aws_secret_access_key, aws_region)\n",
                    "filename": "aws.py",
                    "language": "python",
                    "suggested_commit_message": "Add AWS credentials",
                    "honeytoken_id": "d45a123f-b15d-4fea-abf6-ff2a8479de5b",
                    "gitguardian_url": "https://dashboard.gitguardian.com/workspace/1/honeytokens/d45a123f-b15d-4fea-abf6-ff2a8479de5b",  # noqa: E501
                },
            ),
            (
                SecretIncidentSchema,
                SecretIncident,
                {
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
                    "share_url": "https://dashboard.gitguardian.com/share/incidents/11111111-11111",
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
            ),
            (
                SecretOccurrenceSchema,
                SecretOccurrence,
                {
                    "id": 16424242,
                    "incident_id": 133424242,
                    "author_info": "toto@gitguardian.com",
                    "author_name": "toto@gitguardian.com",
                    "date": "2024-01-17T16:05:43Z",
                    "filepath": ".pre-commit-config.yaml",
                    "kind": "historical",
                    "sha": "ee95f89e211831f07f07e07fde478",
                    "presence": "present",
                    "url": "https://github.com/GitGuardian/py-gitguardian/commit/ee95f89e211831f07f07e07fde478",
                    "matches": [
                        {
                            "name": "connection_uri",
                            "indice_start": 62,
                            "indice_end": 131,
                            "pre_line_start": None,
                            "pre_line_end": None,
                            "post_line_start": 3,
                            "post_line_end": 3,
                        },
                        {
                            "name": "scheme",
                            "indice_start": 62,
                            "indice_end": 70,
                            "pre_line_start": None,
                            "pre_line_end": None,
                            "post_line_start": 3,
                            "post_line_end": 3,
                        },
                        {
                            "name": "username",
                            "indice_start": 73,
                            "indice_end": 81,
                            "pre_line_start": None,
                            "pre_line_end": None,
                            "post_line_start": 3,
                            "post_line_end": 3,
                        },
                        {
                            "name": "password",
                            "indice_start": 82,
                            "indice_end": 99,
                            "pre_line_start": None,
                            "pre_line_end": None,
                            "post_line_start": 3,
                            "post_line_end": 3,
                        },
                        {
                            "name": "host",
                            "indice_start": 100,
                            "indice_end": 112,
                            "pre_line_start": None,
                            "pre_line_end": None,
                            "post_line_start": 3,
                            "post_line_end": 3,
                        },
                        {
                            "name": "port",
                            "indice_start": 113,
                            "indice_end": 117,
                            "pre_line_start": None,
                            "pre_line_end": None,
                            "post_line_start": 3,
                            "post_line_end": 3,
                        },
                        {
                            "name": "database",
                            "indice_start": 118,
                            "indice_end": 131,
                            "pre_line_start": None,
                            "pre_line_end": None,
                            "post_line_start": 3,
                            "post_line_end": 3,
                        },
                    ],
                    "source": {
                        "id": 16218989,
                        "type": "github",
                        "full_name": "py-gitguardian",
                        "health": "at_risk",
                        "source_criticality": "unknown",
                        "default_branch": "main",
                        "default_branch_head": None,
                        "open_incidents_count": 19,
                        "closed_incidents_count": 0,
                        "last_scan": {
                            "date": "2024-08-07T14:15:33.829070Z",
                            "status": "finished",
                            "failing_reason": "",
                            "commits_scanned": 49,
                            "duration": "0.0",
                            "branches_scanned": 14,
                            "progress": 100,
                        },
                        "monitored": True,
                        "visibility": "internal",
                        "external_id": "139",
                        "secret_incidents_breakdown": {
                            "open_secret_incidents": {
                                "total": 19,
                                "severity_breakdown": {
                                    "critical": 0,
                                    "high": 7,
                                    "medium": 0,
                                    "low": 0,
                                    "info": 0,
                                    "unknown": 12,
                                },
                            },
                            "closed_secret_incidents": {
                                "total": 0,
                                "severity_breakdown": {
                                    "critical": 0,
                                    "high": 0,
                                    "medium": 0,
                                    "low": 0,
                                    "info": 0,
                                    "unknown": 0,
                                },
                            },
                        },
                        "url": "https://github.com/GitGuardian/py-gitguardian",
                    },
                    "tags": ["FROM_HISTORICAL_SCAN"],
                },
            ),
        ],
    )
    def test_schema_loads(self, schema_klass, expected_klass, instance_data):
        """
        GIVEN the right kwargs  and an extra field in dict format
        WHEN loading using the schema
        THEN the extra field should be excluded
        AND the result should be an instance of the expected class
        """
        schema = schema_klass()

        data = {**instance_data, "field": "extra"}

        obj = schema.load(data)
        assert isinstance(obj, expected_klass)

    def test_detail_renames_error_field(self):
        """
        GIVEN a Detail JSON dict with an `error` field instead of a `detail` field
        WHEN loading using the schema
        THEN the created Detail instance contains a `detail` field with the right value
        """
        detail = Detail.SCHEMA.load({"error": "An error message"})
        assert detail.detail == "An error message"

    @pytest.mark.parametrize("known_secret", [True, False])
    def test_policy_break_known_secret_field(self, known_secret):
        """
        GIVEN the data with policy breaks
        WHEN loading using the schema
        THEN known_secret is parsed correctly with the default value set to False
        """
        data = {
            "type": "hello",
            "detector_name": "hello",
            "detector_group_name": "hello",
            "documentation_url": None,
            "policy": "hello",
            "validity": "hey",
            "matches": [{"match": "hello", "type": "hello"}],
        }
        if known_secret:
            data["known_secret"] = True

        obj = PolicyBreakSchema().load(data)

        assert obj.known_secret is known_secret
