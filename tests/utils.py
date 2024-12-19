from pygitguardian.models import Invitation, Source, Team, TeamsParameters
from pygitguardian.models_utils import CursorPaginatedResponse

from .conftest import create_client


def get_source() -> Source:
    """
    Return the first source available in the account,
    not all accounts have a source so testing from scratch
    will require installing a source first
    """

    client = create_client()
    paginated_sources = client.list_sources()
    assert isinstance(
        paginated_sources, CursorPaginatedResponse
    ), "Could not fetch sources from GitGuardian"
    return paginated_sources.data[0]


def get_invitation() -> Invitation:
    """
    Return the first invitation available in the account,
    there is no invitation by default, one should be
    created to setup the test
    """

    client = create_client()
    paginated_teams = client.list_invitations()
    assert isinstance(
        paginated_teams, CursorPaginatedResponse
    ), "Could not fetch members from GitGuardian"

    return paginated_teams.data[0]


def get_team() -> Team:
    """
    Return the first team available in the account,
    every account should have at least one team (all incidents)
    but we skip it since we cannot add sources to it
    """

    client = create_client()

    paginated_teams = client.list_teams(TeamsParameters(is_global=False))
    assert isinstance(
        paginated_teams, CursorPaginatedResponse
    ), "Could not fetch teams from GitGuardian"

    return paginated_teams.data[0]
