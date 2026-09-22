from typing import Any, Dict, List, Optional

from pygitguardian.models import APITokensResponse

from .workspace import REQUIRED_SCOPES, WORKSPACE_ID, WORKSPACE_NAME, token_problems


def api_token(
    type: str = "service_account",
    status: str = "active",
    workspace_id: int = WORKSPACE_ID,
    scopes: Optional[List[str]] = None,
) -> APITokensResponse:
    payload: Dict[str, Any] = {
        "id": "5ddaad0c-5a0c-4674-beb5-1cd198d13360",
        "name": "py-gitguardian live tests",
        "workspace_id": workspace_id,
        "type": type,
        "status": status,
        "created_at": "2026-09-22T10:00:00Z",
        "last_used_at": None,
        "expire_at": None,
        "revoked_at": None,
        "member_id": None,
        "creator_id": 1,
        "scopes": sorted(REQUIRED_SCOPES) if scopes is None else scopes,
    }
    result = APITokensResponse.from_dict(payload)
    assert isinstance(result, APITokensResponse)
    return result


def test_token_problems_is_empty_for_the_expected_token():
    """
    GIVEN an active service account token of the test workspace with every
    required scope, plus the read scopes the dashboard adds
    WHEN checking it
    THEN nothing is reported
    """
    token = api_token(scopes=sorted(REQUIRED_SCOPES) + ["members:read", "teams:read"])

    assert token_problems(token) == []


def test_token_problems_rejects_a_personal_access_token():
    """
    GIVEN a personal access token of the test workspace
    WHEN checking it
    THEN it is reported as not being a service account token
    """
    assert token_problems(api_token(type="personal_access_token")) == [
        "the token is a personal_access_token, not a service account token"
    ]


def test_token_problems_rejects_a_revoked_token():
    """
    GIVEN a revoked service account token
    WHEN checking it
    THEN it is reported as not active
    """
    assert token_problems(api_token(status="revoked")) == [
        "the token is revoked, not active"
    ]


def test_token_problems_rejects_another_workspace():
    """
    GIVEN a token of another workspace
    WHEN checking it
    THEN both workspaces are named
    """
    assert token_problems(api_token(workspace_id=42)) == [
        f"the token belongs to workspace 42, not to {WORKSPACE_NAME} ({WORKSPACE_ID})"
    ]


def test_token_problems_lists_the_missing_scopes():
    """
    GIVEN a token with only the scan scope
    WHEN checking it
    THEN the missing scopes are listed, sorted
    """
    assert token_problems(api_token(scopes=["scan"])) == [
        "the token lacks the scopes: ai-discover:send, members:write, "
        "sources:read, teams:write"
    ]


def test_token_problems_requires_the_write_scopes_as_such():
    """
    GIVEN a token with members:read where members:write is required
    WHEN checking it
    THEN members:write is missing, the read scope does not stand in for it
    """
    scopes = sorted(REQUIRED_SCOPES - {"members:write"}) + ["members:read"]

    assert token_problems(api_token(scopes=scopes)) == [
        "the token lacks the scopes: members:write"
    ]
