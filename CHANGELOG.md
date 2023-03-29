# Changelog

<a id='changelog-1.5.1'></a>

## 1.5.1 — 2023-03-29

### Fixed

- Python dependencies were not correctly defined: py-gitguardian was using `marshmallow-dataclass` and `click` without depending on them. The package now explicitly depends on `marshmallow-dataclass` and does not use `click` anymore (#43).

<a id='changelog-1.5.0'></a>

## 1.5.0 - 2022-11-28

### Added

- `Client` can now run IaC scans (gitguardian/ggshield#405).
