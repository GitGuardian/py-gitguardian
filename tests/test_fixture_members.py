from typing import Any, Dict

import pytest

from pygitguardian.models import (
    AccessLevel,
    CreateTeamMember,
    IncidentPermission,
    Member,
    TeamMember,
    UpdateMember,
)

from .fixture_members import (
    EMAIL_PREFIX,
    MANAGER_EMAIL,
    expendable_member,
    fixture_members,
    is_fixture,
    members_parameters,
    pool_problems,
    restorations,
    team_plan,
)


def member(
    email: str,
    access_level: AccessLevel = AccessLevel.MEMBER,
    active: bool = True,
    id: int = 1,
) -> Member:
    payload: Dict[str, Any] = {
        "id": id,
        "access_level": access_level.value,
        "email": email,
        "name": "",
        "created_at": "2026-09-22T10:00:00Z",
        "last_login": None,
        "active": active,
    }
    result = Member.from_dict(payload)
    assert isinstance(result, Member)
    return result


MANAGER = member(MANAGER_EMAIL, AccessLevel.MANAGER, id=1)
MEMBER1 = member(f"{EMAIL_PREFIX}member1@gitguardian.com", id=2)
MEMBER2 = member(f"{EMAIL_PREFIX}member2@gitguardian.com", id=3)
MEMBER3 = member(f"{EMAIL_PREFIX}member3@gitguardian.com", id=6)
HUMAN_MANAGER = member("someone@gitguardian.com", AccessLevel.MANAGER, id=4)
OWNER = member("owner@gitguardian.com", AccessLevel.OWNER, id=5)


@pytest.mark.parametrize(
    ("candidate", "expected"),
    [
        (MANAGER, True),
        (MEMBER1, True),
        (HUMAN_MANAGER, False),
        (member("qa-team-testing+manager@gitguardian.com"), False),
    ],
)
def test_is_fixture_matches_seeded_emails_only(candidate: Member, expected: bool):
    """
    GIVEN a workspace member
    WHEN checking whether the tests may alter it
    THEN only the emails seeded by GIM qualify
    """
    assert is_fixture(candidate) is expected


def test_pool_problems_is_empty_for_a_complete_pool():
    """
    GIVEN the fixture manager and three fixture members, plus humans
    WHEN checking the pool
    THEN nothing is reported
    """
    assert (
        pool_problems([OWNER, HUMAN_MANAGER, MANAGER, MEMBER1, MEMBER2, MEMBER3]) == []
    )


def test_pool_problems_reports_a_missing_manager():
    """
    GIVEN a pool without the fixture manager
    WHEN checking the pool
    THEN the missing manager is named
    """
    problems = pool_problems([OWNER, HUMAN_MANAGER, MEMBER1, MEMBER2, MEMBER3])

    assert len(problems) == 1
    assert MANAGER_EMAIL in problems[0]


def test_pool_problems_reports_too_few_members():
    """
    GIVEN a pool with two fixture members left
    WHEN checking the pool
    THEN the shortage is reported, humans not counting as fixtures
    """
    problems = pool_problems([OWNER, HUMAN_MANAGER, MANAGER, MEMBER1, MEMBER2])

    assert len(problems) == 1
    assert EMAIL_PREFIX in problems[0]


def test_restorations_is_empty_when_the_pool_is_in_its_seeded_state():
    """
    GIVEN every fixture active with its seeded role
    WHEN computing the restorations
    THEN there is nothing to do
    """
    assert restorations([OWNER, HUMAN_MANAGER, MANAGER, MEMBER1, MEMBER2]) == []


def test_restorations_repromotes_and_reactivates_the_fixture_manager():
    """
    GIVEN the fixture manager demoted and deactivated by test_update_member
    WHEN computing the restorations
    THEN it is made an active manager again
    """
    demoted = member(MANAGER_EMAIL, AccessLevel.MEMBER, active=False, id=1)

    assert restorations([demoted, MEMBER1, MEMBER2]) == [
        UpdateMember(1, AccessLevel.MANAGER, active=True)
    ]


def test_restorations_reactivates_a_deactivated_fixture_member():
    """
    GIVEN a deactivated fixture member
    WHEN computing the restorations
    THEN it is reactivated as a member
    """
    deactivated = member(MEMBER2.email, active=False, id=3)

    assert restorations([MANAGER, MEMBER1, deactivated]) == [
        UpdateMember(3, AccessLevel.MEMBER, active=True)
    ]


def test_restorations_never_touch_humans():
    """
    GIVEN a deactivated human manager next to a healthy pool
    WHEN computing the restorations
    THEN the human is left alone
    """
    deactivated_human = member(
        HUMAN_MANAGER.email, AccessLevel.MANAGER, active=False, id=4
    )

    assert restorations([OWNER, deactivated_human, MANAGER, MEMBER1, MEMBER2]) == []


def team_member(
    member: Member, is_team_leader: bool = False, id: int = 100
) -> TeamMember:
    payload: Dict[str, Any] = {
        "id": id,
        "team_id": 7,
        "member_id": member.id,
        "is_team_leader": is_team_leader,
        "team_permission": "can_manage" if is_team_leader else "cannot_manage",
        "incident_permission": "full_access",
    }
    result = TeamMember.from_dict(payload)
    assert isinstance(result, TeamMember)
    return result


POOL = [OWNER, HUMAN_MANAGER, MANAGER, MEMBER1, MEMBER2, MEMBER3]


def test_members_parameters_search_the_fixture_prefix():
    """
    GIVEN a members query
    WHEN built for the fixtures
    THEN it searches the fixture email prefix and keeps the other filters
    """
    parameters = members_parameters(access_level=AccessLevel.MANAGER)

    assert parameters.search == EMAIL_PREFIX
    assert parameters.access_level == AccessLevel.MANAGER


def test_team_plan_seeds_an_empty_team():
    """
    GIVEN a team without fixtures
    WHEN planning its seeded state
    THEN the fixture manager joins as leader and the first fixture member as member
    """
    plan = team_plan([team_member(HUMAN_MANAGER, is_team_leader=True)], POOL)

    assert plan.add == [
        CreateTeamMember(MANAGER.id, True, IncidentPermission.FULL_ACCESS),
        CreateTeamMember(MEMBER1.id, False, IncidentPermission.FULL_ACCESS),
    ]
    assert plan.remove == []


def test_team_plan_leaves_a_seeded_team_alone():
    """
    GIVEN a team with the fixture manager leading and the first fixture member in
    WHEN planning its seeded state
    THEN nothing changes
    """
    team_members = [team_member(MANAGER, is_team_leader=True), team_member(MEMBER1)]

    plan = team_plan(team_members, POOL)

    assert plan.add == []
    assert plan.remove == []


def test_team_plan_removes_the_spare_fixture_added_by_the_tests():
    """
    GIVEN a team where test_create_team_member added the second fixture member
    WHEN planning its seeded state
    THEN that member is removed so the test has one to add next time
    """
    spare = team_member(MEMBER2, id=42)
    team_members = [
        team_member(MANAGER, is_team_leader=True),
        team_member(MEMBER1),
        spare,
    ]

    plan = team_plan(team_members, POOL)

    assert plan.add == []
    assert plan.remove == [spare]


def test_team_plan_restores_the_member_removed_by_the_tests():
    """
    GIVEN a team where test_delete_team_member removed the first fixture member
    WHEN planning its seeded state
    THEN it is added back
    """
    plan = team_plan([team_member(MANAGER, is_team_leader=True)], POOL)

    assert plan.add == [
        CreateTeamMember(MEMBER1.id, False, IncidentPermission.FULL_ACCESS)
    ]
    assert plan.remove == []


def test_team_plan_never_touches_humans():
    """
    GIVEN a team full of humans
    WHEN planning its seeded state
    THEN no human is removed
    """
    humans = [team_member(HUMAN_MANAGER, is_team_leader=True), team_member(OWNER, id=2)]
    team_members = humans + [
        team_member(MANAGER, is_team_leader=True, id=3),
        team_member(MEMBER1, id=4),
    ]

    plan = team_plan(team_members, POOL)

    assert plan.remove == []


# After a GIM reseed, the recreated member1 gets the highest id, so the API lists
# it last while the setup still seats it in the teams
RESEEDED_MEMBER1 = member(MEMBER1.email, id=9)
RESEEDED_POOL = [OWNER, HUMAN_MANAGER, MANAGER, MEMBER2, MEMBER3, RESEEDED_MEMBER1]


def test_expendable_member_is_the_first_by_email_whatever_the_listing_order():
    """
    GIVEN the fixture members listed by ascending id after a reseed
    WHEN picking the member test_delete_member may delete
    THEN it is the first by email, not the first listed
    """
    assert expendable_member(RESEEDED_POOL) == RESEEDED_MEMBER1


def test_team_plan_seats_the_expendable_member():
    """
    GIVEN a reseeded pool
    WHEN planning a team
    THEN the member it seats is the one test_delete_member deletes, so the two
    other fixture members stay free for the two create team member tests
    """
    plan = team_plan([], RESEEDED_POOL)
    expendable = expendable_member(RESEEDED_POOL)
    assert expendable is not None

    seated = [create.member_id for create in plan.add if not create.is_team_leader]
    assert seated == [expendable.id]

    spares = [
        m
        for m in fixture_members(RESEEDED_POOL)
        if m.id not in seated and m != expendable
    ]
    assert len(spares) == 2
