# Changelog

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
