# Users, teams and sources

It is possible to removed all cassettes from this repository and run them all by providing a valid personal access token.

However, for users, teams and sources, this requires a workplace with enough data filled in.

## For source related tests

We require the workplace to have:

- At least two sources

## For member related tests

We require the workplace to have:

- At least two members, they should have different access levels
- At least one invitation sent out

## For team related tests

We require the workplace to have :

- At least two teams
- These teams should have 2 or more members
- These teams should have at least one monitored source in their perimeter
- ⚠️ No team should have all available sources in their perimeter
- There should exist a team where at least one member is not invited
- There should exist one pending team invitation

> Keep in mind that some of these tests will delete resources, so they should run in an isolated workplace
