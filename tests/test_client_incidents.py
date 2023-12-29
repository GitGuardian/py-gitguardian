import json
from collections import OrderedDict
from datetime import datetime
from uuid import uuid4

import pytest
import responses

from pygitguardian import GGClient
from pygitguardian.incident_models import (
    Incident,
    ListIncidentResult,
    SharedIncidentDetails,
)
from pygitguardian.incident_models.constants import (
    IncidentPermission,
    IncidentSeverity,
    IncidentStatus,
)
from pygitguardian.models import Detail


def make_incident(idx):
    return {
        "id": idx,
        "gitguardian_url": f"https://dashboard.gitguardian.com/workspace/0/incidents/{idx}",
        "assignee_id": 0,
        "assignee_email": "john.smith@example.com",
        "date": "2020-10-29T13:19:59.005564Z",
        "detector": {
            "name": "aws_iam",
            "display_name": "AWS Keys",
            "nature": "specific",
            "family": "Api",
            "detector_group_name": "aws_iam",
            "detector_group_display_name": "AWS Keys",
        },
        "ignore_reason": None,
        "ignored_at": None,
        "ignorer_api_token_id": None,
        "ignorer_id": None,
        "occurrences": None,
        "tags": ["PUBLIC"],
        "occurrences_count": 2,
        "regression": False,
        "resolved_at": "2022-09-06T09:06:08.295495Z",
        "resolver_api_token_id": None,
        "resolver_id": None,
        "secret_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "secret_revoked": True,
        "status": "RESOLVED",
        "validity": "invalid",
        "share_url": None,
        "severity": "medium",
    }


def make_occurrence(idx, incident_id):
    return {
        "author_info": "john.smith@example.com",
        "author_name": "John Smith",
        "date": "2020-10-20T01:19:28.788008Z",
        "filepath": "app.py",
        "id": idx,
        "incident_id": incident_id,
        "kind": "realtime",
        "matches": [
            {
                "name": "client_secret",
                "indice_start": 150,
                "indice_end": 169,
                "pre_line_start": 4,
                "pre_line_end": 4,
                "post_line_start": None,
                "post_line_end": None,
            },
            {
                "name": "client_id",
                "indice_start": 49,
                "indice_end": 134,
                "pre_line_start": 3,
                "pre_line_end": 3,
                "post_line_start": None,
                "post_line_end": None,
            },
        ],
        "presence": "removed",
        "sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "location": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "source": {
            "id": 12367,
            "url": "https://git.example.com/group/repo",
            "type": "github",
            "full_name": "group/repo",
            "health": "at_risk",
            "open_incidents_count": 7,
            "closed_incidents_count": 6,
            "visibility": "public",
            "last_scan": {"date": "2020-09-24T09:06:39.257426Z", "status": "finished"},
            "external_id": "83385",
        },
        "url": "https://git.example.com/group/repo/commit/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "tags": ["PUBLIC"],
    }


def make_share_response(idx, feedback_collection=False):
    token = str(uuid4())
    return {
        "share_url": f"https://dashboard.gitguardian.com/share/incidents/{token}",
        "incident_id": idx,
        "feedback_collection": feedback_collection,
        "auto_healing": False,
        "token": token,
        "expire_at": "2023-07-01T14:47:42.939558Z",
        "revoked_at": None,
    }


def make_incident_with_occurrences(idx, occurrences_count):
    incident = make_incident(idx)
    incident["occurrences_count"] = int(occurrences_count)
    incident["occurrences"] = [
        make_occurrence(i, idx) for i in range(int(occurrences_count))
    ]
    return incident


def test_list_secret_incidents(client: GGClient):
    with responses.RequestsMock() as rsps:
        rsps.add(
            responses.GET,
            "https://api.gitguardian.com/v1/incidents/secrets",
            body=json.dumps([make_incident(i) for i in range(20)]),
            status=200,
            content_type="application/json",
        )
        response = client.list_secret_incidents()
        assert response.status_code == 200
        assert isinstance(response, ListIncidentResult)
        assert isinstance(response.incidents, list)
        assert len(response.incidents) == 20
        assert isinstance(response.incidents[0], Incident)
        assert isinstance(response.to_dict(), OrderedDict)
        response_json = response.to_json()
        assert isinstance(response_json, str)
        loaded_response = ListIncidentResult.SCHEMA.load(json.loads(response_json))
        assert loaded_response == response


def test_list_secret_incidents_10_per_page(client: GGClient):
    with responses.RequestsMock() as rsps:
        rsps.add(
            responses.GET,
            "https://api.gitguardian.com/v1/incidents/secrets",
            match=[responses.matchers.query_param_matcher({"per_page": 10})],
            body=json.dumps([make_incident(i) for i in range(10)]),
            status=200,
            content_type="application/json",
        )
        response = client.list_secret_incidents(per_page=10)
        assert response.status_code == 200
        assert isinstance(response, ListIncidentResult)
        assert len(response.incidents) == 10
        print(response.links)


def test_list_secret_incidents_date_before(client: GGClient):
    with responses.RequestsMock() as rsps:
        rsps.add(
            responses.GET,
            "https://api.gitguardian.com/v1/incidents/secrets",
            match=[
                responses.matchers.query_param_matcher(
                    {"date_before": "2022-12-31 00:00:00+00:00"}
                )
            ],
            body=json.dumps([make_incident(i) for i in range(10)]),
            status=200,
            content_type="application/json",
        )
        response = client.list_secret_incidents(
            date_before=datetime.fromisoformat("2022-12-31T00:00:00+00:00")
        )
        assert response.status_code == 200


def test_list_secret_incidents_date_after(client: GGClient):
    with responses.RequestsMock() as rsps:
        rsps.add(
            responses.GET,
            "https://api.gitguardian.com/v1/incidents/secrets",
            match=[
                responses.matchers.query_param_matcher(
                    {"date_after": "2022-12-31 00:00:00+00:00"}
                )
            ],
            body=json.dumps([make_incident(i) for i in range(10)]),
            status=200,
            content_type="application/json",
        )
        response = client.list_secret_incidents(
            date_after=datetime.fromisoformat("2022-12-31T00:00:00+00:00")
        )
        assert response.status_code == 200


def test_list_secret_incidents_assignee_email(client: GGClient):
    with responses.RequestsMock() as rsps:
        rsps.add(
            responses.GET,
            "https://api.gitguardian.com/v1/incidents/secrets",
            match=[
                responses.matchers.query_param_matcher(
                    {"assignee_email": "bruce-wayne-gg@protonmail.com"}
                )
            ],
            body=json.dumps([make_incident(i) for i in range(10)]),
            status=200,
            content_type="application/json",
        )
        response = client.list_secret_incidents(
            assignee_email="bruce-wayne-gg@protonmail.com"
        )
        assert response.status_code == 200


def test_list_secret_incidents_assignee_id(client: GGClient):
    with responses.RequestsMock() as rsps:
        rsps.add(
            responses.GET,
            "https://api.gitguardian.com/v1/incidents/secrets",
            match=[responses.matchers.query_param_matcher({"assignee_id": "10"})],
            body=json.dumps([make_incident(i) for i in range(10)]),
            status=200,
            content_type="application/json",
        )
        response = client.list_secret_incidents(assignee_id=10)
        assert response.status_code == 200


def test_iter_incidents_all(client: GGClient):
    with responses.RequestsMock() as rsps:
        rsps.add(
            responses.GET,
            "https://api.gitguardian.com/v1/incidents/secrets",
            match=[responses.matchers.query_param_matcher({"per_page": "10"})],
            body=json.dumps([make_incident(i) for i in range(10)]),
            status=200,
            content_type="application/json",
        )
        for idx, incident in enumerate(client.iter_incidents(per_page=10)):
            assert isinstance(incident, Incident)
            if idx > 30:
                break


def test_iter_incidents_ignored(client: GGClient):
    with responses.RequestsMock() as rsps:
        rsps.add(
            responses.GET,
            "https://api.gitguardian.com/v1/incidents/secrets",
            match=[
                responses.matchers.query_param_matcher(
                    {"per_page": "10", "status": "IGNORED"}
                )
            ],
            body=json.dumps([make_incident(i) for i in range(10)]),
            status=200,
            headers={
                "link": "<https://api.gitguardian.com/v1/incidents/secrets"
                '?cursor=cD0yMTU0NQ%3D%3D&per_page=10&status=IGNORED>; rel="next"'
            },
            content_type="application/json",
        )
        rsps.add(
            responses.GET,
            "https://api.gitguardian.com/v1/incidents/secrets",
            match=[
                responses.matchers.query_param_matcher(
                    {"per_page": "10", "status": "IGNORED", "cursor": "cD0yMTU0NQ=="}
                )
            ],
            body=json.dumps([make_incident(i) for i in range(10)]),
            status=200,
            headers={
                "link": "<https://api.gitguardian.com/v1/incidents/secrets"
                '?cursor=cD0yMTk4Ng%3D%3D&per_page=10&status=IGNORED>; rel="next"'
            },
            content_type="application/json",
        )
        rsps.add(
            responses.GET,
            "https://api.gitguardian.com/v1/incidents/secrets",
            match=[
                responses.matchers.query_param_matcher(
                    {"per_page": "10", "status": "IGNORED", "cursor": "cD0yMTk4Ng=="}
                )
            ],
            body=json.dumps([make_incident(i) for i in range(5)]),
            status=200,
            content_type="application/json",
        )
        for idx, incident in enumerate(
            client.iter_incidents(per_page=10, status=IncidentStatus.IGNORED)
        ):
            assert isinstance(incident, Incident)
        assert idx == 24


def test_get_secret_incident_without_occurrences(client: GGClient):
    with responses.RequestsMock() as rsps:
        rsps.add(
            responses.GET,
            "https://api.gitguardian.com/v1/incidents/secrets/1",
            match=[responses.matchers.query_param_matcher({"with_occurrences": "0"})],
            body=json.dumps(make_incident(0)),
            status=200,
            content_type="application/json",
        )
        response = client.get_secret_incident(incident_id=1, with_occurrences=0)
        assert response.status_code == 200
        assert isinstance(response, Incident)
        assert isinstance(response.to_dict(), OrderedDict)
        response_json = response.to_json()
        assert isinstance(response_json, str)
        loaded_response = Incident.SCHEMA.load(json.loads(response_json))
        assert loaded_response == response


def test_get_secret_incident_with_occurrences(client: GGClient):
    with responses.RequestsMock() as rsps:
        rsps.add(
            responses.GET,
            "https://api.gitguardian.com/v1/incidents/secrets/1",
            match=[responses.matchers.query_param_matcher({"with_occurrences": "1"})],
            body=json.dumps(make_incident_with_occurrences(1, 2)),
            status=200,
            content_type="application/json",
        )
        response = client.get_secret_incident(incident_id=1, with_occurrences=1)
        assert response.status_code == 200
        assert isinstance(response, Incident)
        assert response.occurrences is not None
        assert len(response.occurrences) > 0
        assert isinstance(response.to_dict(), OrderedDict)
        response_json = response.to_json()
        assert isinstance(response_json, str)
        loaded_response = Incident.SCHEMA.load(json.loads(response_json))
        assert loaded_response == response


def test_update_incident_severity(client: GGClient):
    with responses.RequestsMock() as rsps:
        rsps.add(
            responses.PATCH,
            "https://api.gitguardian.com/v1/incidents/secrets/1",
            match=[responses.matchers.json_params_matcher({"severity": "medium"})],
            body=json.dumps(make_incident(1)),
            status=200,
            content_type="application/json",
        )
        incident = client.update_incident_severity(
            incident_id=1, severity=IncidentSeverity.MEDIUM
        )
        assert isinstance(incident, Incident)
        assert incident.status_code == 200
        assert incident.occurrences is None


def test_share_incident(client: GGClient):
    with responses.RequestsMock() as rsps:
        rsps.add(
            responses.POST,
            "https://api.gitguardian.com/v1/incidents/secrets/1/share",
            body=json.dumps(make_share_response(1)),
            status=200,
            content_type="application/json",
        )
        response = client.share_incident(incident_id=1)
        assert response.status_code == 200
        assert isinstance(response, SharedIncidentDetails)
        assert isinstance(response.to_dict(), OrderedDict)
        loaded_response = SharedIncidentDetails.SCHEMA.load(
            json.loads(response.to_json())
        )
        assert loaded_response == response


def test_share_incident_with_obj(client: GGClient):
    with responses.RequestsMock() as rsps:
        rsps.add(
            responses.POST,
            "https://api.gitguardian.com/v1/incidents/secrets/1/share",
            body=json.dumps(make_share_response(1)),
            status=200,
            content_type="application/json",
        )
        incident = Incident.from_dict(make_incident(1))
        response = client.share_incident(incident_id=incident)
        assert response.status_code == 200
        assert isinstance(response, SharedIncidentDetails)
        assert isinstance(response.to_dict(), OrderedDict)
        loaded_response = SharedIncidentDetails.SCHEMA.load(
            json.loads(response.to_json())
        )
        assert loaded_response == response


def test_share_incident_with_feedback(client: GGClient):
    with responses.RequestsMock() as rsps:
        rsps.add(
            responses.POST,
            "https://api.gitguardian.com/v1/incidents/secrets/1/share",
            match=[
                responses.matchers.query_param_matcher({"feedback_collection": "True"})
            ],
            body=json.dumps(make_share_response(1, True)),
            status=200,
            content_type="application/json",
        )
        response = client.share_incident(incident_id=1, feedback_collection=True)
        assert response.status_code == 200
        assert isinstance(response, SharedIncidentDetails)
        assert response.feedback_collection
        assert isinstance(response.to_dict(), OrderedDict)
        loaded_response = SharedIncidentDetails.SCHEMA.load(
            json.loads(response.to_json())
        )
        assert loaded_response == response


def test_unshare_incident(client: GGClient):
    with responses.RequestsMock() as rsps:
        rsps.add(
            responses.POST,
            "https://api.gitguardian.com/v1/incidents/secrets/1/unshare",
            body="",
            status=204,
            content_type="application/json",
        )
        response = client.unshare_incident(1)
        assert response


def test_unshare_unshared_incident(client: GGClient):
    with responses.RequestsMock() as rsps:
        rsps.add(
            responses.POST,
            "https://api.gitguardian.com/v1/incidents/secrets/1/unshare",
            body='{"detail":"Issue is not shared"}',
            status=409,
            content_type="application/json",
        )
        response = client.unshare_incident(1)
        assert isinstance(response, Detail)
        assert response.status_code == 409


def test_grant_access_to_incident(client: GGClient):
    with responses.RequestsMock() as rsps:
        rsps.add(
            responses.POST,
            "https://api.gitguardian.com/v1/incidents/secrets/1/grant_access",
            match=[
                responses.matchers.query_param_matcher(
                    {
                        "incident_permission": "full_access",
                        "member_id": 1234,
                    }
                )
            ],
            status=204,
        )
        response = client.grant_access_to_incident(
            incident_id=1,
            incident_permission=IncidentPermission.FULL_ACCESS,
            member_id=1234,
        )
        assert response


def test_grant_access_to_incident_mutually_exclusive(client: GGClient):
    with pytest.raises(ValueError):
        client.grant_access_to_incident(
            incident_id=1,
            incident_permission=IncidentPermission.FULL_ACCESS,
            email="foo@example.com",
            member_id=1234,
        )


def test_revoke_access_to_incident(client: GGClient):
    with responses.RequestsMock() as rsps:
        rsps.add(
            responses.POST,
            "https://api.gitguardian.com/v1/incidents/secrets/1/revoke_access",
            match=[
                responses.matchers.query_param_matcher(
                    {
                        "member_id": 1234,
                    }
                )
            ],
            status=204,
        )
        response = client.revoke_access_to_incident(
            incident_id=1,
            member_id=1234,
        )
        assert response


def test_revoke_access_to_incident_mutually_exclusive(client: GGClient):
    with pytest.raises(ValueError):
        client.revoke_access_to_incident(
            incident_id=1,
            email="foo@example.com",
            member_id=1234,
        )
