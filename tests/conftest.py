import os
from os.path import dirname, join, realpath
from typing import Any

import pytest
import vcr

from pygitguardian import GGClient
from pygitguardian.models import TeamsParameter
from pygitguardian.models_utils import CursorPaginatedResponse


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


@pytest.fixture
def get_team(client: GGClient):
    """
    Return a function that fetches the first team available
    in the account, every account should have at least
    one team (all incidents) but we skip it since we cannot
    add sources to it
    """

    def inner():
        paginated_teams = client.list_teams(TeamsParameter(is_global=False))
        assert isinstance(
            paginated_teams, CursorPaginatedResponse
        ), "Could not fetch teams from GitGuardian"

        return paginated_teams.data[0]

    return inner


@pytest.fixture
def get_source(client: GGClient):
    """
    Return a function that fetches the first source available
    in the account, not all accounts have a source so testing
    from scratch will require installing a source first
    """

    def inner():
        paginated_sources = client.list_sources()
        assert isinstance(
            paginated_sources, CursorPaginatedResponse
        ), "Could not fetch sources from GitGuardian"
        return paginated_sources.data[0]

    return inner


@pytest.fixture
def get_member(client: GGClient):
    """
    Return a function that fetches the first member available
    in the account, every account should have at least
    one member (the owner)
    """

    def inner():
        paginated_teams = client.list_members()
        assert isinstance(
            paginated_teams, CursorPaginatedResponse
        ), "Could not fetch members from GitGuardian"

        return paginated_teams.data[0]

    return inner


@pytest.fixture
def get_invitation(client: GGClient):
    """
    Return a function that fetches the first invitation available
    in the account, there is no invitation by default, one should be
    created to setup the test
    """

    def inner():
        paginated_teams = client.list_invitations()
        assert isinstance(
            paginated_teams, CursorPaginatedResponse
        ), "Could not fetch members from GitGuardian"

        return paginated_teams.data[0]

    return inner
