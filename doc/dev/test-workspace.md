# The test workspace

The live tests run against the workspace "PyGitGuardian Tests [internal]".
CI only replays `tests/cassettes` and never reaches it.

## Fixture accounts

Tests only write to accounts whose email starts with
`qa-team-testing+gglibraries-`: one Manager and at least 3 Members. Every other
member is a human and is never touched.

The API cannot create members, so a GitGuardian engineer with production access
seeds them:

```
python manage.py seed_gglibraries_test_workspace --account-id <workspace id>
```

Each full live run deletes one member: reseed before the next one.

## The token

A service account token of the workspace, Manager access level, with the scopes
`scan`, `members:write`, `teams:write`, `sources:read` and `ai-discover:send`.
It is in the Endpoints vault of the password manager. `scripts/release run-tests`
checks it before touching anything.

## Running the live suite

```
scripts/release run-tests
```

To record a single test, delete its cassette and run it with
`GITGUARDIAN_API_KEY` set. List members with `members_parameters()` so
recordings hold no real people, and run
`pre-commit run prettier --files tests/cassettes/<name>.yaml` before committing.
