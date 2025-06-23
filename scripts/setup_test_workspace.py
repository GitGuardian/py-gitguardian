"""
Notice: This script will attempt to setup a test workspace on GitGuardian.
This will allow the user to run tests without relying on cassettes, note that
there are a few limitations due to actions that cannot be performed through
the API, notably :
- Create the workspace
- We cannot create members, so there must exist a minimum amount of members in the workspace
    - This also means deleted members cannot be brought back from the script
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
    CreateTeamMember,
    Detail,
    IncidentPermission,
    InvitationParameters,
    Member,
    MembersParameters,
    Source,
    Team,
    TeamMember,
    TeamsParameters,
    UpdateMember,
    UpdateTeamSource,
)
from pygitguardian.models_utils import FromDictWithBase
from tests.utils import CursorPaginatedResponse


client = GGClient(
    api_key=os.environ["GITGUARDIAN_API_KEY"],
    base_uri=os.environ.get("GITGUARDIAN_API_URL"),
)

T = TypeVar("T")
PaginatedDataType = TypeVar("PaginatedDataType", bound=FromDictWithBase)

MIN_NB_TEAM = 2
MIN_NB_MEMBER = 4  # 1 owner, 1 manager and at least two members
MIN_NB_TEAM_MEMBER = 2
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
    This function ensures that the workspace :
    - Has no deactivated members
        - If there are, they will be activated
    - Has at most 1 admin / manager (excluding owner)
        - It may demote some manager to member
    - There is at least `MIN_NB_MEMBER`
    """

    deactivated_members = unwrap_paginated_response(
        client.list_members(MembersParameters(active=False))
    )
    for member in deactivated_members:
        client.update_member(UpdateMember(member.id, AccessLevel.MEMBER, active=True))

    admin_members = unwrap_paginated_response(
        client.list_members(MembersParameters(access_level=AccessLevel.MANAGER))
    )

    if len(admin_members) > 1:
        for member in admin_members[1:]:
            ensure_success(
                client.update_member(UpdateMember(member.id, AccessLevel.MEMBER))
            )
    else:
        members = unwrap_paginated_response(
            client.list_members(MembersParameters(access_level=AccessLevel.MEMBER))
        )
        assert (
            len(members) > 0
        ), "There must be at least one member with access level member in the workspace"

        ensure_success(
            client.update_member(UpdateMember(members[0].id, AccessLevel.MANAGER))
        )

    members = ensure_success(client.list_members(MembersParameters(per_page=5)))

    assert (
        len(members.data) >= MIN_NB_MEMBER
    ), f"There must be at least {MIN_NB_MEMBER} members in the workspace"


def add_source_to_team(team: Team, available_sources: Iterable[Source] | None = None):
    if available_sources is None:
        available_sources = ensure_success(client.list_sources()).data

    ensure_success(
        client.update_team_source(
            UpdateTeamSource(team.id, [source.id for source in available_sources], [])
        )
    )


def add_team_members(
    team: Team,
    team_members: Iterable[TeamMember],
    nb_members: int,
    available_members: Iterable[Member] | None = None,
):
    assert nb_members > 0, "We should add at least one member"
    if available_members is None:
        available_members = unwrap_paginated_response(client.list_members())

    # Every manager is by default a team leader
    has_admin = any(team_member.is_team_leader for team_member in team_members)

    if not has_admin:
        admin_member = next(
            (
                member
                for member in available_members
                if member.access_level == AccessLevel.MANAGER
            ),
            None,
        )
        assert admin_member is not None, "There should be at least one admin member"

        ensure_success(
            client.create_team_member(
                team.id,
                CreateTeamMember(
                    admin_member.id,
                    is_team_leader=True,
                    incident_permission=IncidentPermission.FULL_ACCESS,
                ),
            )
        )
        nb_members -= 1

    team_member_ids = {team_member.member_id for team_member in team_members}
    for _ in range(nb_members):
        to_add_member = next(
            (
                member
                for member in available_members
                if member.id not in team_member_ids
                and member.access_level not in {AccessLevel.OWNER, AccessLevel.MANAGER}
            ),
            None,
        )
        assert to_add_member is not None, "There is not enough members in the workspace"
        is_team_leader = False
        permissions = IncidentPermission.FULL_ACCESS

        if to_add_member.access_level == AccessLevel.MANAGER:
            is_team_leader = True

        ensure_success(
            client.create_team_member(
                team.id,
                CreateTeamMember(
                    to_add_member.id,
                    is_team_leader=is_team_leader,
                    incident_permission=permissions,
                ),
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
    - Every team has at least 2 members, an admin and a member
        - If possible, it will try to add those members
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

    # Ensure every team has:
    # - At least one source
    # - At least two members, one with admin access and one with member access
    for team in teams:
        team_members = unwrap_paginated_response(client.list_team_members(team.id))
        nb_team_members = len(team_members)
        if nb_team_members < MIN_NB_TEAM_MEMBER:
            add_team_members(team, team_members, MIN_NB_TEAM_MEMBER - nb_team_members)

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
