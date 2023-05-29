# Changelog

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
