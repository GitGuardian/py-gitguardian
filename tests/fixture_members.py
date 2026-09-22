"""
Members of the "PyGitGuardian Tests [internal]" workspace (628984) that the live
tests may demote, deactivate or delete.

GIM's ``seed_gglibraries_test_workspace`` command creates them. Every other
member is a human and must be left alone.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from pygitguardian.models import (
    AccessLevel,
    CreateTeamMember,
    IncidentPermission,
    Member,
    MembersParameters,
    TeamMember,
    UpdateMember,
)


EMAIL_PREFIX = "qa-team-testing+gglibraries-"
MANAGER_EMAIL = f"{EMAIL_PREFIX}manager@gitguardian.com"
# One for test_delete_member, two for the team member tests
MIN_MEMBERS = 3
SEED_COMMAND = "python manage.py seed_gglibraries_test_workspace --account-id 628984"


def members_parameters(**kwargs: Any) -> MembersParameters:
    """
    Members query returning the fixtures whatever the size of the workspace: the
    API searches emails and the fixtures share a prefix, so one page holds them all
    """
    return MembersParameters(search=EMAIL_PREFIX, **kwargs)


def is_fixture(member: Member) -> bool:
    return member.email.startswith(EMAIL_PREFIX)


def fixture_manager(members: Iterable[Member]) -> Optional[Member]:
    return next((m for m in members if m.email == MANAGER_EMAIL), None)


def fixture_members(members: Iterable[Member]) -> List[Member]:
    """Fixtures other than the manager, whatever their current role or state"""
    return [m for m in members if is_fixture(m) and m.email != MANAGER_EMAIL]


def pool_problems(members: Iterable[Member]) -> List[str]:
    """Reasons the tests must not run against this pool, empty when they may"""
    members = list(members)
    problems = []
    if fixture_manager(members) is None:
        problems.append(f"{MANAGER_EMAIL} is not a member of the workspace")
    count = len(fixture_members(members))
    if count < MIN_MEMBERS:
        problems.append(
            f"{count} member(s) with an email starting with {EMAIL_PREFIX}, "
            f"at least {MIN_MEMBERS} are needed"
        )
    return problems


def restorations(members: Iterable[Member]) -> List[UpdateMember]:
    """
    Updates putting every fixture back in its seeded state: the manager active
    as manager, the others active as members
    """
    updates = []
    for member in members:
        if not is_fixture(member):
            continue
        expected = (
            AccessLevel.MANAGER if member.email == MANAGER_EMAIL else AccessLevel.MEMBER
        )
        if member.active and member.access_level == expected:
            continue
        updates.append(UpdateMember(member.id, expected, active=True))
    return updates


@dataclass
class TeamPlan:
    add: List[CreateTeamMember] = field(default_factory=list)
    remove: List[TeamMember] = field(default_factory=list)


def team_plan(
    team_members: Iterable[TeamMember], fixtures: Iterable[Member]
) -> TeamPlan:
    """
    Changes putting a team in its seeded state: the fixture manager leads it, the
    first fixture member belongs to it, the other fixture members stay out. This
    leaves test_create_team_member a fixture to add and test_delete_team_member one
    to remove, whoever else is in the team.
    """
    fixtures = list(fixtures)
    manager = fixture_manager(fixtures)
    members = sorted(fixture_members(fixtures), key=lambda member: member.email)
    wanted: Dict[int, bool] = {}
    if manager is not None:
        wanted[manager.id] = True
    if members:
        wanted[members[0].id] = False
    spare_ids = {member.id for member in members[1:]}

    present = {team_member.member_id: team_member for team_member in team_members}
    plan = TeamPlan()
    for member_id, is_team_leader in wanted.items():
        if member_id not in present:
            plan.add.append(
                CreateTeamMember(
                    member_id, is_team_leader, IncidentPermission.FULL_ACCESS
                )
            )
    plan.remove = [
        team_member
        for member_id, team_member in present.items()
        if member_id in spare_ids
    ]
    return plan
