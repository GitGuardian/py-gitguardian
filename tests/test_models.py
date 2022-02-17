from typing import OrderedDict

import pytest

from pygitguardian.models import (
    Document,
    DocumentSchema,
    HealthCheckResponseSchema,
    Match,
    MatchSchema,
    MultiScanResult,
    MultiScanResultSchema,
    PolicyBreak,
    PolicyBreakSchema,
    Quota,
    QuotaResponse,
    QuotaResponseSchema,
    QuotaSchema,
    ScanResult,
    ScanResultSchema,
)


class TestModel:
    def test_document_model(self):
        """
        GIVEN a simple document
        THEN base model methods should produce the appropriate types.
        """
        document = Document("hello", "hello")
        assert isinstance(document.to_json(), str)
        assert isinstance(document.to_dict(), dict)
        assert isinstance(str(document), str)

    @pytest.mark.parametrize(
        "schema_klass, expected_klass, instance_data",
        [
            (DocumentSchema, OrderedDict, {"filename": "hello", "document": "hello"}),
            (
                HealthCheckResponseSchema,
                OrderedDict,
                {"detail": "hello", "status_code": 200},
            ),
            (MatchSchema, Match, {"match": "hello", "type": "hello"}),
            (
                MultiScanResultSchema,
                MultiScanResult,
                {
                    "scan_results": [
                        {
                            "policy_break_count": 1,
                            "policies": ["pol"],
                            "policy_breaks": [
                                {
                                    "type": "break",
                                    "policy": "mypol",
                                    "matches": [
                                        {
                                            "match": "hello",
                                            "type": "hello",
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                    "type": "hello",
                },
            ),
            (
                PolicyBreakSchema,
                PolicyBreak,
                {
                    "type": "hello",
                    "policy": "hello",
                    "validity": "hey",
                    "matches": [{"match": "hello", "type": "hello"}],
                },
            ),
            (
                QuotaSchema,
                Quota,
                {
                    "count": 1,
                    "limit": 1,
                    "remaining": 1,
                    "since": "2021-04-18",
                },
            ),
            (
                QuotaResponseSchema,
                QuotaResponse,
                {
                    "content": {
                        "count": 1,
                        "limit": 1,
                        "remaining": 1,
                        "since": "2021-04-18",
                    }
                },
            ),
            (
                ScanResultSchema,
                ScanResult,
                {"policy_break_count": 1, "policy_breaks": [], "policies": []},
            ),
        ],
    )
    def test_schema_loads(self, schema_klass, expected_klass, instance_data):
        """
        GIVEN the right kwargs  and an extra field in dict format
        WHEN loading using the schema
        THEN the extra field should be excluded
            AND the result should be an instance of the expected class
        """
        schema = schema_klass()

        data = {**instance_data, "field": "extra"}

        obj = schema.load(data)
        assert isinstance(obj, expected_klass)
