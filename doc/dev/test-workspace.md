# The test workspace

The live test suite runs against the GitGuardian workspace
"PyGitGuardian Tests [internal]" (id 628984), a real workspace reserved for the
tests of the GitGuardian libraries. Its constants live in `tests/workspace.py`
and `tests/fixture_members.py`.

## What the live suite does to the workspace

Most tests only read. The member and team tests write, always on the fixture
accounts described below:

- `test_update_member` demotes the fixture manager to member and deactivates it
- `test_delete_member` deletes the expendable fixture member
- the team member tests seat fixture members in teams and remove them
- the team and invitation tests create teams and invitations and delete them

`scripts/setup_test_workspace.py` runs before the suite and puts the workspace
back in its seeded state: every fixture active with its seeded role, every team
led by the fixture manager with the expendable member in it and the other
fixtures out, leftover test teams and invitations deleted.

## Fixture accounts

The accounts the tests may alter share the email prefix
`qa-team-testing+gglibraries-` (`EMAIL_PREFIX`):

- `qa-team-testing+gglibraries-manager@gitguardian.com`, a Manager
  (`MANAGER_EMAIL`)
- `qa-team-testing+gglibraries-member1@gitguardian.com`, `member2`, and so on,
  plain Members

The suite needs the manager and at least `MIN_MEMBERS` (3) members: one to
delete, two for the create team member tests. Every other member of the
workspace is a human and is never touched: the code picks the fixtures by
email, never by position in a listing.

## Seeding

The API cannot create members, so the fixtures are seeded by a management
command of the GitGuardian backend (`SEED_COMMAND`), run by a GitGuardian
engineer with production access before each release:

```
python manage.py seed_gglibraries_test_workspace --account-id 628984
```

It recreates the missing fixtures and is the only way a deleted member comes
back. Every full run of the suite consumes one member, so reseed before running
it a second time; the setup script stops with this command when the pool is
short.

## The token

The suite authenticates with a service account token of the workspace, created
with the Manager access level and these scopes:

- `scan`
- `members:write`
- `teams:write`
- `sources:read`
- `ai-discover:send`

It is kept in the Endpoints team's password manager and loaded into
`GITGUARDIAN_API_KEY`. Before touching anything, `scripts/release run-tests`
checks it against `GET /v1/api_tokens/self` and stops with the reason when the
token is rejected, is a personal access token, is not active, belongs to another
workspace or lacks a scope.

## Cassettes

CI replays the recordings in `tests/cassettes` and never reaches the workspace;
`GITGUARDIAN_API_KEY` only needs to be set. Cassettes are re-recorded on
purpose only, by the live run before a release or by hand for one test. Two
rules for recordings:

- list members with `members_parameters()` from `tests/fixture_members.py`: it
  searches the fixture prefix, so a recording never contains real people
- run `pre-commit run prettier --files tests/cassettes/<name>.yaml` on freshly
  recorded YAML before committing it

## Running the live suite

With the token loaded, from the release branch:

```
scripts/release run-tests
```

It checks the token, wipes the cassettes, runs the setup script, runs the whole
suite live and restores the cassettes from git. Add `--dev-mode` before
`run-tests` to run it from another branch or with a dirty working tree.

## Running a single test live

Delete its cassette, run it with the token, then format the new recording:

```
rm tests/cassettes/test_delete_member.yaml
GITGUARDIAN_API_KEY=<token> pdm run pytest tests/test_client.py -k test_delete_member
pre-commit run prettier --files tests/cassettes/test_delete_member.yaml
```

A test that writes to the workspace expects the seeded state; run
`pdm run scripts/setup_test_workspace.py` first when in doubt.
