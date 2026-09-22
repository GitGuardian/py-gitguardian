"""
Members of the "PyGitGuardian Tests [internal]" workspace (628984) that the live
tests may demote, deactivate or delete.

GIM's ``seed_gglibraries_test_workspace`` command creates them. Every other
member is a human and must be left alone.
"""

from typing import Iterable, List, Optional

from pygitguardian.models import AccessLevel, Member, UpdateMember


EMAIL_PREFIX = "qa-team-testing+gglibraries-"
MANAGER_EMAIL = f"{EMAIL_PREFIX}manager@gitguardian.com"
# One for test_delete_member, one left for the team tests
MIN_MEMBERS = 2
SEED_COMMAND = "python manage.py seed_gglibraries_test_workspace --account-id 628984"


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
