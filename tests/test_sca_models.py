import pytest

from pygitguardian.sca_models import (
    ComputeSCAFilesResult,
    SCAIgnoredVulnerability,
    SCALocationVulnerability,
    SCAScanAllOutput,
    SCAScanDiffOutput,
    SCAScanParameters,
    SCAVulnerability,
    SCAVulnerablePackageVersion,
)


class TestModel:
    @pytest.mark.parametrize(
        "expected_klass, instance_data",
        [
            (
                SCAIgnoredVulnerability,
                {
                    "identifier": "GHSA-toto",
                    "path": "Pipfile",
                },
            ),
            (
                SCAScanParameters,
                {
                    "miniumu_severity": "LOW",
                    "ignored_vulnerabilities": [
                        {
                            "identifier": "GHSA-toto",
                            "path": "Pipfile",
                        }
                    ],
                },
            ),
            (
                ComputeSCAFilesResult,
                {
                    "sca_files": ["Pipfile", "package-lock.json"],
                    "potential_siblings": ["Pipfile.lock", "package.json"],
                },
            ),
            (
                SCAVulnerability,
                {
                    "severity": "LOW",
                    "summary": "toto",
                    "identifier": "foo",
                    "cve_ids": ["CVE_1", "CVE_2"],
                    "created_at": None,
                    "fixed_version": "1.2.3",
                },
            ),
            (
                SCAVulnerablePackageVersion,
                {
                    "package_full_name": "toto",
                    "version": "1.2.4",
                    "ecosystem": "pypi",
                    "dependency_type": "direct",
                    "vulns": [
                        {
                            "severity": "LOW",
                            "summary": "toto",
                            "identifier": "foo",
                            "cve_ids": ["CVE_1", "CVE_2"],
                            "created_at": None,
                            "fixed_version": "1.2.3",
                        }
                    ],
                },
            ),
            (
                SCALocationVulnerability,
                {
                    "location": "toto",
                    "package_vulns": [
                        {
                            "package_full_name": "toto",
                            "version": "1.2.4",
                            "ecosystem": "pypi",
                            "dependency_type": "direct",
                            "vulns": [
                                {
                                    "severity": "LOW",
                                    "summary": "toto",
                                    "identifier": "foo",
                                    "cve_ids": ["CVE_1", "CVE_2"],
                                    "created_at": None,
                                    "fixed_version": "1.2.3",
                                }
                            ],
                        }
                    ],
                },
            ),
            (
                SCAScanAllOutput,
                {
                    "scanned_files": ["toto"],
                    "found_package_vulns": [
                        {
                            "location": "toto",
                            "package_vulns": [
                                {
                                    "package_full_name": "toto",
                                    "version": "1.2.4",
                                    "ecosystem": "pypi",
                                    "dependency_type": "direct",
                                    "vulns": [
                                        {
                                            "severity": "LOW",
                                            "summary": "toto",
                                            "identifier": "foo",
                                            "cve_ids": ["CVE_1", "CVE_2"],
                                            "created_at": None,
                                            "fixed_version": "1.2.3",
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                },
            ),
            (
                SCAScanDiffOutput,
                {
                    "scanned_files": ["toto"],
                    "added_vulns": [
                        {
                            "location": "toto",
                            "package_vulns": [
                                {
                                    "package_full_name": "toto",
                                    "version": "1.2.4",
                                    "ecosystem": "pypi",
                                    "dependency_type": "direct",
                                    "vulns": [
                                        {
                                            "severity": "LOW",
                                            "summary": "toto",
                                            "identifier": "foo",
                                            "cve_ids": ["CVE_1", "CVE_2"],
                                            "created_at": None,
                                            "fixed_version": "1.2.3",
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                    "removed_vulns": [
                        {
                            "location": "toto",
                            "package_vulns": [
                                {
                                    "package_full_name": "toto",
                                    "version": "1.2.4",
                                    "ecosystem": "pypi",
                                    "dependency_type": "direct",
                                    "vulns": [
                                        {
                                            "severity": "LOW",
                                            "summary": "toto",
                                            "identifier": "foo",
                                            "cve_ids": ["CVE_1", "CVE_2"],
                                            "created_at": None,
                                            "fixed_version": "1.2.3",
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                },
            ),
        ],
    )
    def test_schema_loads(self, expected_klass, instance_data):
        """
        GIVEN the right kwargs and an extra field in dict format
        WHEN loading using the schema
        THEN the extra field is not taken into account
        AND the result should be an instance of the expected class
        """
        schema = expected_klass.SCHEMA

        data = {**instance_data, "field": "extra"}

        obj = schema.load(data)
        assert isinstance(obj, expected_klass)
