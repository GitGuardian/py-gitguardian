# Changelog

<a id='changelog-1.34.0'></a>

## 1.34.0 — 2026-08-19

### Added

- `AgentInfo.subscription_email`: the email of the assistant subscription an AI agent is signed into, so a personal
  subscription can be told apart from a company one. Optional — agents that keep no account readable on disk send nothing.

### Fixed

- `Source.last_scan.status`, `Source.health`, `Source.source_criticality`, `Member.access_level`, `Invitation.access_level`, `TeamMember`/`TeamInvitation` permission fields, and related models no longer raise `marshmallow.exceptions.ValidationError` when the API returns a value added after this SDK version (e.g. the new `skipped`/`launched`/`running_failed`/`running_cancelled` scan statuses). These fields now accept any string, falling back to the raw value for statuses/levels the SDK doesn't have a named constant for yet, instead of failing to deserialize the whole object.

<a id='changelog-1.33.1'></a>

## 1.33.1 — 2026-07-28

### Fixed

- Fix `create_honeytoken_with_context()` that treated every successful response as an error: 1.33.0 started requiring a `201` status, but the `/v1/honeytokens/with-context` endpoint answers `200`. Successful responses were parsed as an error `Detail`, raising a `ValidationError`.

<a id='changelog-1.33.0'></a>

## 1.33.0 — 2026-07-28

### Added

- New endpoint `send_agent_activity()`: ship a batch of raw AI-agent activity records (one per transcript line or database row) to GitGuardian and receive ingested/duplicate counts. Adds the `AgentActivityResponse` model. Records are opaque to the SDK and sent verbatim; GitGuardian scans the content and strips secrets server-side before storing it. Optionally carries the reporting machine/user (a serialised `UserInfo`) so records can be attributed and correlated with the machine inventory. The response reports ingested/duplicate/dropped counts (dropped = records the server could not scan and refused to store).

- AI discovery now also sends whether hooks are globally installed, per agent.

- New `ai-discover:send` token scope.

### Changed

- Update MCP endpoint paths from `nhi/ai/...` to `agent-activity/...` following server-side route migration.

### Fixed

- `api_tokens()` and `create_honeytoken_with_context()` now return a `Detail` instead of raising a raw `JSONDecodeError` when the server answers a `2xx` with a non-JSON body (e.g. an HTML page served when the instance URL is wrong). Like the other endpoints, they now gate JSON parsing on the response status and content type.

<a id='changelog-1.32.0'></a>

## 1.32.0 — 2026-06-16

### Changed

- The library is now compatible with marshmallow 4 (`marshmallow>=3.18, <5`). On Python 3.9+ marshmallow 4 is used; Python 3.8 keeps marshmallow 3. As a result, `to_dict()` and `from_dict()` now return a plain `dict` instead of an `OrderedDict` (insertion order is still preserved). `marshmallow-dataclass` is bumped to `>=8.7, <8.8`.

### Deprecated

- Python 3.8 support is deprecated and will be removed in a future release. Importing the library on Python 3.8 now emits a `DeprecationWarning`. Upgrade to Python 3.9+.

<a id='changelog-1.31.0'></a>

## 1.31.0 — 2026-06-15

### Added

- New endpoint `log_mcp_activities_bulk()`: send a batch of historical `MCPActivityRequest` to GitGuardian and receive ingested/duplicate counts. Adds `MCPActivityBulkResponse` model.

- Optional `timestamp` field on `MCPActivityRequest`, used by the bulk endpoint to record historical events. Live (single-event) `log_mcp_activity` callers are unaffected; the new field defaults to `None`.

- New `endpoints:send` token scope.

<a id='changelog-1.30.0'></a>

## 1.30.0 — 2026-04-28

### Added

- `scan_and_create_incidents`: documents now accept an optional `location` field containing an http/https URL identifying the origin of the document.

- New endpoints `send_ai_discovery()` and `log_mcp_activity`, with associated models.

- New `honeytokens:check` token scope for prefix-based honeytoken lookup.

<a id='changelog-1.29.0'></a>

## 1.29.0 — 2026-01-27

### Added

- Capture secret incident `custom_tags` dictionaries when calling `retrieve_secret_incident`.

<a id='changelog-1.28.0'></a>

## 1.28.0 — 2025-12-29

### Fixed

- MembersParameters, TeamInvitationParameters, and TeamMembershipParameters now properly apply pagination and search queries.

<a id='changelog-1.27.0'></a>

## 1.27.0 — 2025-11-14

### Changed

- Changed the following fields to `str`: `visibility`, `kind`, `presence status`, `ignore_reason`, `tag`.

<a id='changelog-1.26.0'></a>

## 1.26.0 — 2025-10-27

### Fixed

- Missing scope leading to validation errors

<a id='changelog-1.25.0'></a>

## 1.25.0 — 2025-08-26

### Changed

- Updated `Client.scan_and_create_incidents()` to match server-side API changes.

<a id='changelog-1.24.0'></a>

## 1.24.0 — 2025-07-28

### Added

- Added `GGClient.scan_and_create_incidents()` function to scan content for secrets and automatically create incidents.

- Added `vault_type`, `vault_name`, `vault_path` and `vault_path_count` fields to `PolicyBreak`.

<a id='changelog-1.23.0'></a>

## 1.23.0 — 2025-06-23

### Changed

- Set PolicyBreak's detector_name and detector_group_name fields as optional to fix backwards compatibility with the GitGuardian API

<a id='changelog-1.22.0'></a>

## 1.22.0 — 2025-05-26

### Added

- Added `is_vaulted` field to `PolicyBreak`.

<a id='changelog-1.21.0'></a>

## 1.21.0 — 2025-04-29

### Added

- Added extra information to scan results: detector name, detector group name, and documentation URL.

### Fixed

- Added missing scopes to the `TokenScope` enum.

<a id='changelog-1.20.0'></a>

## 1.20.0 — 2025-02-25

### Removed

- Removed support for the deprecated SCA and IaC endpoints.

<a id='changelog-1.19.0'></a>

## 1.19.0 — 2025-01-07

### Added

- Added support for members and teams endpoints.
- Added support for invitations endpoints.
- Added support for sources endpoints.

<a id='changelog-1.18.0'></a>

## 1.18.0 — 2024-11-25

### Added

- Added the `is_diff` attribute to `ScanResult`.

- Added the following attributes to `PolicyBreak`: `diff_kind`, `is_excluded` and `exclude_reason`.

- `GGClient` now provides a `api_tokens()` method to retrieve API token details (see https://api.gitguardian.com/docs#tag/API-Tokens).

### Changed

- `GGClient.content_scan()` and `GGClient.multi_content_scan()` now accept an `all_secrets` parameter.

### Fixed

- Add missing value `info` to Severity model (#120).

<a id='changelog-1.17.0'></a>

## 1.17.0 — 2024-09-23

### Added

- `GGClient` now provides a `retrieve_secret_incident()` method to retrieve the dashboard incident associated with a secret (see https://api.gitguardian.com/docs#tag/Secret-Incidents/operation/retrieve-incidents).

<a id='changelog-1.16.0'></a>

## 1.16.0 — 2024-07-29

### Added

- `GGClient` now contains remediation messages obtained from the API `/metadata` endpoint.

<a id='changelog-1.15.2'></a>

## 1.15.2 — 2024-06-24

### Changed

- The project now uses [pdm](https://pdm-project.org/) instead of pipenv.

### Fixed

- `GGClient` no longer crashes when it receives a server response with no Content-Type header.

<a id='changelog-1.15.1'></a>

## 1.15.1 — 2024-06-24

Yanked: release process issue.

<a id='changelog-1.15.0'></a>

## 1.15.0 — 2024-06-24

Yanked: release process issue.

<a id='changelog-1.14.0'></a>

## 1.14.0 — 2024-02-26

### Added

- Add `GGClient.create_honeytoken_with_context()` method.

- Export scan schemas in addition to dataclasses for sca.

<a id='changelog-1.13.0'></a>

## 1.13.0 — 2024-01-30

### Added

- Added maximum payload size as a property of GGClient.

### Changed

- Set minimum Python version to >=3.8.

<a id='changelog-1.12.0'></a>

## 1.12.0 — 2024-01-08

### Added

- `GGClient` now obeys rate-limits and can notify callers when hitting one.

- Added the following attributes to `IaCVulnerability`: `url`, `status`, `ignored_until`, `ignore_reason`, `ignore_comment`.

- Added the `source_found` attribute to `IaCScanParameters` and `IaCDiffScanEntities`.

<a id='changelog-1.11.0'></a>

## 1.11.0 — 2023-10-16

### Added

- Added `extra_headers` to SCA diff scans.

<a id='changelog-1.10.0'></a>

## 1.10.0 — 2023-09-26

### Fixed

- Remove `potential_siblings` from models.

<a id='changelog-1.9.0'></a>

## 1.9.0 — 2023-08-10

### Added

- Added the `GGClient.iac_diff_scan()` method. This allows scanning two directories for IaC vulnerabilities and categorizing incidents as new, unchanged or deleted.

### Fixed

- Fixed a bug where py-gitguardian would sometimes increase the length of a document when preparing it to be sent to the secret scan API.

<a id='changelog-1.8.0'></a>

## 1.8.0 — 2023-06-26

### Added

- Added `GGClient.create_jwt()` method. This is only used to interact with HasMySecretLeaked for now.

- py-gitguardian is now fully type-hinted (#49).

### Changed

- All HTTP requests are now logged using Python logger. The log message includes the HTTP method, endpoint, status code and duration.

### Fixed

- `GGClient.iac_directory_scan()` was not correctly sending the files to scan.

<a id='changelog-1.7.0'></a>

## 1.7.0 — 2023-05-29

### Added

- Added `GGClient.create_honeytoken()` method.

- Added `GGClient.read_metadata()` to read metadata from the server. The metadata is then used by further secret scan calls and is available in a new `GGClient.secret_scan_preferences` attribute.

<a id='changelog-1.6.0'></a>

## 1.6.0 — 2023-04-20

### Added

- The `PolicyBreak` class now includes the URL of the policy break if the dashboard already knows about it.

<a id='changelog-1.5.1'></a>

## 1.5.1 — 2023-03-29

### Fixed

- Python dependencies were not correctly defined: py-gitguardian was using `marshmallow-dataclass` and `click` without depending on them. The package now explicitly depends on `marshmallow-dataclass` and does not use `click` anymore (#43).

<a id='changelog-1.5.0'></a>

## 1.5.0 — 2022-11-28

### Added

- `Client` can now run IaC scans (gitguardian/ggshield#405).
