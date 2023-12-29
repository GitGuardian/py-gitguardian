import pytest

from pygitguardian.incident_models import Detector, Incident, Match, Occurrence


class TestModel:
    @pytest.mark.parametrize(
        "klass, instance_data",
        [
            (
                Detector,
                {
                    "name": "slack_bot_token",
                    "display_name": "Slack Bot Token",
                    "nature": "specific",
                    "family": "apikey",
                    "detector_group_name": "slackbot_token",
                    "detector_group_display_name": "Slack Bot Token",
                },
            ),
            (
                Match,
                {
                    "name": "apikey",
                    "indice_start": 32,
                    "indice_end": 79,
                    "pre_line_start": None,
                    "pre_line_end": None,
                    "post_line_start": 1,
                    "post_line_end": 1,
                },
            ),
            (
                Occurrence,
                {
                    "id": 4421,
                    "incident_id": 3759,
                    "kind": "realtime",
                    "sha": "d670460b4b4aece5915caf5c68d12f560a9fe3e4",
                    "source": {
                        "id": 6531,
                        "url": "https://github.com/GitGuardian/gg-shield",
                        "type": "github",
                        "full_name": "gitguardian/gg-shield",
                        "health": "at_risk",
                        "open_incidents_count": 3,
                        "closed_incidents_count": 2,
                        "visibility": "public",
                        "external_id": "125",
                        "last_scan": {
                            "date": "2021-05-20T12:40:55.662949Z",
                            "status": "finished",
                        },
                    },
                    "author_name": "Eric",
                    "author_info": "eric@gitguardian.com",
                    "date": "2021-05-20T12:40:55.662949Z",
                    "presence": "present",
                    "url": (
                        "https://github.com/prm-dev-team/QATest_staging/commit/"
                        "76dd18a2a8d27eaf00a45851cc7731c53b59ed19"
                        "#diff-0f372f3171c8f13a15a22a1081487ed54fa70ad088e17c6c6386196a179a04ffR1"
                    ),
                    "matches": [
                        {
                            "name": "apikey",
                            "indice_start": 32,
                            "indice_end": 79,
                            "pre_line_start": None,
                            "pre_line_end": None,
                            "post_line_start": 1,
                            "post_line_end": 1,
                        }
                    ],
                    "filepath": "test_data/12123testfile.txt",
                },
            ),
            (
                # Unresolved incident without ocurrences - returned from list endpoint
                Incident,
                {
                    "id": 3759,
                    "date": "2019-08-22T14:15:22Z",
                    "detector": {
                        "name": "slack_bot_token",
                        "display_name": "Slack Bot Token",
                        "nature": "specific",
                        "family": "apikey",
                        "detector_group_name": "slackbot_token",
                        "detector_group_display_name": "Slack Bot Token",
                    },
                    "secret_hash": "Ri9FjVgdOlPnBmujoxP4XPJcbe82BhJXB/SAngijw/juCISuOMgPzYhV28m6OG24",
                    "gitguardian_url": "https://dashboard.gitguardian.com/workspace/1/incidents/3899",
                    "regression": False,
                    "status": "IGNORED",
                    "assignee_email": "eric@gitguardian.com",
                    "occurrences_count": 4,
                    "occurrences": None,
                    "ignore_reason": "test_credential",
                    "ignored_at": "2019-08-24T14:15:22Z",
                    "secret_revoked": False,
                    "severity": "high",
                    "validity": "valid",
                    "resolved_at": None,
                    "share_url": (
                        "https://dashboard.gitguardian.com"
                        "/share/incidents/11111111-1111-1111-1111-111111111111"
                    ),
                    "tags": ["FROM_HISTORICAL_SCAN", "SENSITIVE_FILE"],
                },
            ),
            (
                # Resolved incident without ocurrences - returned from list endpoint
                Incident,
                {
                    "id": 3759,
                    "date": "2019-08-22T14:15:22Z",
                    "detector": {
                        "name": "slack_bot_token",
                        "display_name": "Slack Bot Token",
                        "nature": "specific",
                        "family": "apikey",
                        "detector_group_name": "slackbot_token",
                        "detector_group_display_name": "Slack Bot Token",
                    },
                    "secret_hash": "Ri9FjVgdOlPnBmujoxP4XPJcbe82BhJXB/SAngijw/juCISuOMgPzYhV28m6OG24",
                    "gitguardian_url": "https://dashboard.gitguardian.com/workspace/1/incidents/3899",
                    "regression": False,
                    "status": "IGNORED",
                    "assignee_email": "eric@gitguardian.com",
                    "occurrences_count": 4,
                    "occurrences": None,
                    "ignore_reason": "test_credential",
                    "ignored_at": "2019-08-24T14:15:22Z",
                    "secret_revoked": False,
                    "severity": "high",
                    "validity": "valid",
                    "resolved_at": None,
                    "share_url": (
                        "https://dashboard.gitguardian.com"
                        "/share/incidents/11111111-1111-1111-1111-111111111111"
                    ),
                    "tags": ["FROM_HISTORICAL_SCAN", "SENSITIVE_FILE"],
                },
            ),
            (
                # Ignored incident with ocurrences - returned from
                # /v1/incidents/secrets/{incident_id}
                Incident,
                {
                    "id": 3759,
                    "date": "2019-08-22T14:15:22Z",
                    "detector": {
                        "name": "slack_bot_token",
                        "display_name": "Slack Bot Token",
                        "nature": "specific",
                        "family": "apikey",
                        "detector_group_name": "slackbot_token",
                        "detector_group_display_name": "Slack Bot Token",
                    },
                    "secret_hash": "Ri9FjVgdOlPnBmujoxP4XPJcbe82BhJXB/SAngijw/juCISuOMgPzYhV28m6OG24",
                    "gitguardian_url": "https://dashboard.gitguardian.com/workspace/1/incidents/3899",
                    "regression": False,
                    "status": "IGNORED",
                    "assignee_id": 309,
                    "assignee_email": "eric@gitguardian.com",
                    "occurrences_count": 4,
                    "occurrences": [
                        {
                            "id": 4421,
                            "incident_id": 3759,
                            "kind": "realtime",
                            "sha": "d670460b4b4aece5915caf5c68d12f560a9fe3e4",
                            "source": {
                                "id": 6531,
                                "url": "https://github.com/GitGuardian/gg-shield",
                                "type": "github",
                                "full_name": "gitguardian/gg-shield",
                                "health": "at_risk",
                                "open_incidents_count": 3,
                                "closed_incidents_count": 2,
                                "visibility": "public",
                                "external_id": "125",
                                "last_scan": {
                                    "date": "2021-05-20T12:40:55.662949Z",
                                    "status": "finished",
                                },
                            },
                            "author_name": "Eric",
                            "author_info": "eric@gitguardian.com",
                            "date": "2021-05-20T12:40:55.662949Z",
                            "presence": "present",
                            "url": (
                                "https://github.com/prm-dev-team/QATest_staging/commit/"
                                "76dd18a2a8d27eaf00a45851cc7731c53b59ed19"
                                "#diff-0f372f3171c8f13a15a22a1081487ed54fa70ad088e17c6c6386196a179a04ffR1"
                            ),
                            "matches": [
                                {
                                    "name": "apikey",
                                    "indice_start": 32,
                                    "indice_end": 79,
                                    "pre_line_start": None,
                                    "pre_line_end": None,
                                    "post_line_start": 1,
                                    "post_line_end": 1,
                                }
                            ],
                            "filepath": "test_data/12123testfile.txt",
                        }
                    ],
                    "ignore_reason": "test_credential",
                    "severity": "high",
                    "validity": "valid",
                    "ignored_at": "2019-08-24T14:15:22Z",
                    "ignorer_id": 309,
                    "ignorer_api_token_id": "fdf075f9-1662-4cf1-9171-af50568158a8",
                    "resolver_id": 395,
                    "resolver_api_token_id": "fdf075f9-1662-4cf1-9171-af50568158a8",
                    "secret_revoked": False,
                    "resolved_at": None,
                    "share_url": (
                        "https://dashboard.gitguardian.com"
                        "/share/incidents/11111111-1111-1111-1111-111111111111"
                    ),
                    "tags": ["FROM_HISTORICAL_SCAN", "SENSITIVE_FILE"],
                },
            ),
        ],
    )
    def test_schema_loads(self, klass, instance_data):
        """
        GIVEN the right kwargs and an extra field in dict format
        WHEN loading using the schema
        THEN the extra field is not taken into account
            AND the result should be an instance of the expected class
        """
        data = {**instance_data, "field": "extra"}

        obj = klass.from_dict(data)
        assert isinstance(obj, klass)
