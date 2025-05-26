# Changelog

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
