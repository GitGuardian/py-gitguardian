"""
The GitGuardian workspace the live tests run against, and what the token loaded
in GITGUARDIAN_API_KEY must look like to run them.
"""

from enum import Enum
from typing import Any, List

from pygitguardian.models import APITokensResponse, TokenStatus, TokenType


WORKSPACE_ID = 628984
WORKSPACE_NAME = "PyGitGuardian Tests [internal]"
REQUIRED_SCOPES = frozenset(
    {"scan", "members:write", "teams:write", "sources:read", "ai-discover:send"}
)


def _raw(value: Any) -> Any:
    # LenientEnum keeps values it does not know as strings
    return value.value if isinstance(value, Enum) else value


def token_problems(token: APITokensResponse) -> List[str]:
    """Reasons the live tests must not run with this token, empty when they may"""
    problems = []
    if token.type != TokenType.SERVICE_ACCOUNT:
        problems.append(
            f"the token is a {_raw(token.type)}, not a service account token"
        )
    if token.status != TokenStatus.ACTIVE:
        problems.append(f"the token is {_raw(token.status)}, not active")
    if token.workspace_id != WORKSPACE_ID:
        problems.append(
            f"the token belongs to workspace {token.workspace_id}, "
            f"not to {WORKSPACE_NAME} ({WORKSPACE_ID})"
        )
    missing = sorted(REQUIRED_SCOPES - set(token.scopes))
    if missing:
        problems.append(f"the token lacks the scopes: {', '.join(missing)}")
    return problems
