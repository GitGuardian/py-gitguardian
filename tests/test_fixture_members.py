from typing import Any, Dict

import pytest

from pygitguardian.models import AccessLevel, Member, UpdateMember

from .fixture_members import (
    EMAIL_PREFIX,
    MANAGER_EMAIL,
    is_fixture,
    pool_problems,
    restorations,
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
    GIVEN the fixture manager and two fixture members, plus humans
    WHEN checking the pool
    THEN nothing is reported
    """
    assert pool_problems([OWNER, HUMAN_MANAGER, MANAGER, MEMBER1, MEMBER2]) == []


def test_pool_problems_reports_a_missing_manager():
    """
    GIVEN a pool without the fixture manager
    WHEN checking the pool
    THEN the missing manager is named
    """
    problems = pool_problems([OWNER, HUMAN_MANAGER, MEMBER1, MEMBER2])

    assert len(problems) == 1
    assert MANAGER_EMAIL in problems[0]


def test_pool_problems_reports_too_few_members():
    """
    GIVEN a pool with a single fixture member left
    WHEN checking the pool
    THEN the shortage is reported, humans not counting as fixtures
    """
    problems = pool_problems([OWNER, HUMAN_MANAGER, MANAGER, MEMBER1])

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
