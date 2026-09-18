import pytest

from pygitguardian.models import (
    AgentActivityResponse,
    AgentActivityResponseSchema,
    AgentInfo,
    AgentInfoSchema,
    AIDiscovery,
    AIDiscoverySchema,
    APITokensResponse,
    APITokensResponseSchema,
    Detail,
    DetailSchema,
    DiffKind,
    Document,
    DocumentSchema,
    HealthCheckResponseSchema,
    HoneytokenResponse,
    HoneytokenResponseSchema,
    HoneytokenWithContextResponse,
    HoneytokenWithContextResponseSchema,
    Match,
    MatchSchema,
    MCPActivityRequest,
    MCPActivityRequestSchema,
    MCPActivityResponse,
    MCPActivityResponseSchema,
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

from .conftest import create_secret_incident_payload


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
            (DocumentSchema, dict, {"filename": "hello", "document": "hello"}),
            (
                HealthCheckResponseSchema,
                dict,
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
                    "scopes": ["incidents:read", "scan", "unplanned:scope"],
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
                    "is_vaulted": False,
                    "vault_type": None,
                    "vault_name": None,
                    "vault_path": None,
                    "vault_path_count": None,
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
                    "is_vaulted": True,
                    "vault_type": "hashicorpvault",
                    "vault_name": "my-vault",
                    "vault_path": "my-secret",
                    "vault_path_count": 3,
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
                create_secret_incident_payload(),
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
            (
                AgentInfoSchema,
                AgentInfo,
                {
                    "name": "cursor",
                    "hooks_installed": True,
                },
            ),
            (
                AgentInfoSchema,
                AgentInfo,
                {
                    "name": "cursor",
                    "hooks_installed": True,
                    "hooks_command": "ggshield hooks install cursor",
                },
            ),
            (
                AIDiscoverySchema,
                AIDiscovery,
                {
                    "user": {
                        "user_email": "toto@gitguardian.com",
                        "hostname": "toto-laptop",
                        "username": "toto",
                        "machine_id": "1234567890",
                    },
                    "discovery_duration": 10.0,
                    "servers": [
                        {
                            "name": "mcp-server",
                            "url": "https://mcp-server.com",
                        },
                        {
                            "name": "mcp-server",
                            "url": "https://mcp-server.com",
                        },
                    ],
                    "agents": [
                        {
                            "name": "cursor",
                            "hooks_installed": True,
                            "hooks_command": "ggshield hooks install cursor",
                        },
                    ],
                },
            ),
            (
                MCPActivityRequestSchema,
                MCPActivityRequest,
                {
                    "user": {
                        "user_email": "toto@gitguardian.com",
                        "machine_id": "1234567890",
                        "hostname": "toto-laptop",
                        "username": "toto",
                    },
                    "tool": "list-todos",
                    "server": "https://mcp-server.com",
                    "agent": "cursor",
                    "model": "gpt-4o",
                    "cwd": "/home/user/project",
                    "input": {"key": "value"},
                },
            ),
            (
                MCPActivityResponseSchema,
                MCPActivityResponse,
                {
                    "allowed": True,
                    "reason": "test",
                },
            ),
            (
                AgentActivityResponseSchema,
                AgentActivityResponse,
                {
                    "ingested": 2,
                    "dropped": 0,
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

    def test_policy_break_accepts_unknown_diff_kind(self):
        """
        GIVEN a policy break whose diff kind holds a value added to the API after
        this version of py-gitguardian was released
        WHEN loading using the schema
        THEN the policy break loads and the unknown value is kept as-is
        """
        data = {
            "type": "hello",
            "policy": "hello",
            "validity": "hey",
            "matches": [{"match": "hello", "type": "hello"}],
            "diff_kind": "modification",
        }

        obj = PolicyBreakSchema().load(data)

        assert obj.diff_kind == "modification"

    def test_policy_break_keeps_known_diff_kind_as_enum(self):
        """
        GIVEN a policy break with a diff kind this version knows about
        WHEN loading using the schema
        THEN the value is still turned into a DiffKind member
        """
        data = {
            "type": "hello",
            "policy": "hello",
            "validity": "hey",
            "matches": [{"match": "hello", "type": "hello"}],
            "diff_kind": "deletion",
        }

        obj = PolicyBreakSchema().load(data)

        assert obj.diff_kind is DiffKind.DELETION

    def test_api_tokens_response_accepts_unknown_type_and_status(self):
        """
        GIVEN a token whose type and status hold values added to the API after this
        version of py-gitguardian was released
        WHEN loading using the schema
        THEN the token loads and both unknown values are kept as-is
        """
        payload = {
            "id": "5ddaad0c-5a0c-4674-beb5-1cd198d13360",
            "name": "myTokenName",
            "workspace_id": 42,
            "type": "machine_identity",
            "status": "suspended",
            "created_at": "2023-05-20T12:40:55.662949Z",
            "last_used_at": None,
            "expire_at": None,
            "revoked_at": None,
            "member_id": None,
            "creator_id": None,
            "scopes": ["scan"],
        }

        token = APITokensResponse.SCHEMA.load(payload)

        assert token.type == "machine_identity"
        assert token.status == "suspended"

    def test_secret_incident_accepts_unknown_severity_and_validity(self):
        """
        GIVEN an incident whose severity and validity hold values added to the API
        after this version of py-gitguardian was released
        WHEN loading using the schema
        THEN the incident loads and both unknown values are kept as-is
        """
        payload = create_secret_incident_payload(
            severity="catastrophic",
            validity="cannot_check",
        )

        incident = SecretIncident.SCHEMA.load(payload)

        assert incident.severity == "catastrophic"
        assert incident.validity == "cannot_check"
