"""
Notice: This script will attempt to setup a test workspace on GitGuardian.
This will allow the user to run tests without relying on cassettes, note that
there are a few limitations due to actions that cannot be performed through
the API, notably :
- Create the workspace
- We cannot create members: the ones the tests alter are seeded by GIM's
  `seed_gglibraries_test_workspace` command (see tests/fixture_members.py), and a
  deleted one only comes back by running that command again
- We cannot integrate a source entirely from the public API
    - There must exist a source in the workspace
"""

import os
from typing import Iterable, List, TypeVar

from pygitguardian.client import GGClient
from pygitguardian.models import (
    AccessLevel,
    CreateInvitation,
    CreateTeam,
    CreateTeamInvitation,
    Detail,
    IncidentPermission,
    InvitationParameters,
    Source,
    Team,
    TeamsParameters,
    UpdateTeamSource,
)
from pygitguardian.models_utils import FromDictWithBase
from tests.fixture_members import (
    SEED_COMMAND,
    members_parameters,
    pool_problems,
    restorations,
    team_plan,
)
from tests.utils import CursorPaginatedResponse


client = GGClient(
    api_key=os.environ["GITGUARDIAN_API_KEY"],
    base_uri=os.environ.get("GITGUARDIAN_API_URL"),
)

T = TypeVar("T")
PaginatedDataType = TypeVar("PaginatedDataType", bound=FromDictWithBase)

MIN_NB_TEAM = 2
# This is the team that is created in the tests, it should be deleted before we run the tests
PYGITGUARDIAN_TEST_TEAM = "PyGitGuardian team"


def ensure_success(var: T | Detail) -> T:
    if not isinstance(var, Detail):
        return var
    else:
        raise TypeError(var.detail)


def unwrap_paginated_response(
    var: CursorPaginatedResponse[PaginatedDataType] | Detail,
) -> List[PaginatedDataType]:
    data = ensure_success(var)

    return data.data


def ensure_member_coherence():
    """
    Put the fixture members back in their seeded state (the manager active as
    manager, the others active as members) and stop before any test runs when
    the pool is too small. The other members are humans and are never touched.
    """
    members = unwrap_paginated_response(
        client.list_members(members_parameters(per_page=100))
    )

    problems = pool_problems(members)
    if problems:
        details = "".join(f"\n- {problem}" for problem in problems)
        raise SystemExit(
            f"The fixture pool of the test workspace is short:{details}\n"
            f"Reseed it from a GIM pod: {SEED_COMMAND}"
        )

    for update in restorations(members):
        ensure_success(client.update_member(update))


def add_source_to_team(team: Team, available_sources: Iterable[Source] | None = None):
    if available_sources is None:
        available_sources = ensure_success(client.list_sources()).data

    ensure_success(
        client.update_team_source(
            UpdateTeamSource(team.id, [source.id for source in available_sources], [])
        )
    )


def ensure_team_coherence():
    """
    This function ensures that the workspace :
    - Has no team with name prefixed by `PYGITGUARDIAN_TEST_TEAM`
    - At least `MIN_NB_TEAM` exist
        - If not they will be created
    - Every team has at least one source
        - If possible, it will try to add at least one source
    - Every team is in its seeded state: the fixture manager leads it and the
      first fixture member belongs to it, the other fixtures stay out
    """

    pygitguardian_teams = []
    try:
        pygitguardian_teams = unwrap_paginated_response(
            client.list_teams(TeamsParameters(search=PYGITGUARDIAN_TEST_TEAM))
        )
    except TypeError as exc:
        if str(exc) != "Team not found.":
            raise
    finally:
        for team in pygitguardian_teams:
            ensure_success(client.delete_team(team.id))

    teams = unwrap_paginated_response(
        # exclude global team since we can't add sources / members to it
        client.list_teams(TeamsParameters(is_global=False))
    )

    nb_teams = len(teams)
    if nb_teams < MIN_NB_TEAM:
        for i in range(MIN_NB_TEAM - nb_teams):
            new_team = ensure_success(
                client.create_team(CreateTeam(name=f"PyGitGuardian Team {i}"))
            )
            teams.append(new_team)

    fixtures = unwrap_paginated_response(
        client.list_members(members_parameters(per_page=100))
    )
    for team in teams:
        team_members = unwrap_paginated_response(client.list_team_members(team.id))
        plan = team_plan(team_members, fixtures)
        for create in plan.add:
            ensure_success(client.create_team_member(team.id, create))
        for team_member in plan.remove:
            ensure_success(client.delete_team_member(team.id, team_member.id))

        team_sources = unwrap_paginated_response(client.list_team_sources(team.id))
        nb_team_sources = len(team_sources)
        if nb_team_sources == 0:
            add_source_to_team(team)


def ensure_invitation_coherence():
    """
    This function ensures that the workspace :
    - Has no invitation for emails starting with `pygitguardian`
    - There is at least one pending invitation
        - If not, an invitation will be sent to `pygitguardian@example.com`
    - All team have attached team invitations
        - If not, they will be created
    """

    test_invitation = unwrap_paginated_response(
        client.list_invitations(InvitationParameters(search="pygitguardian"))
    )

    for invitation in test_invitation:
        ensure_success(client.delete_invitation(invitation.id))
    invitations = unwrap_paginated_response(client.list_invitations())

    if len(invitations) < 1:
        invitation = ensure_success(
            client.create_invitation(
                CreateInvitation(
                    email="pygitguardian@invitation.com",
                    access_level=AccessLevel.MEMBER,
                )
            )
        )
        invitations.append(invitation)

    teams = unwrap_paginated_response(client.list_teams())
    invitation = invitations[0]
    for team in teams:
        team_invitations = unwrap_paginated_response(
            client.list_team_invitations(team.id)
        )
        if not team_invitations:
            ensure_success(
                client.create_team_invitation(
                    team.id,
                    CreateTeamInvitation(
                        invitation_id=invitation.id,
                        is_team_leader=False,
                        incident_permission=IncidentPermission.FULL_ACCESS,
                    ),
                )
            )


def main():
    ensure_member_coherence()
    ensure_team_coherence()
    ensure_invitation_coherence()

    print("Test workspace has been set up properly")


if __name__ == "__main__":
    main()
