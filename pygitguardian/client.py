import logging
import os
import platform
import tarfile
import time
import urllib.parse
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Union, cast

import requests
from requests import Response, Session

from .config import DEFAULT_API_VERSION, DEFAULT_BASE_URI, DEFAULT_TIMEOUT
from .iac_models import (
    IaCDiffScanResult,
    IaCScanParameters,
    IaCScanParametersSchema,
    IaCScanResult,
)
from .incident_models import (
    Incident,
    IncidentIdOrIncident,
    ListIncidentResult,
    SharedIncidentDetails,
)
from .incident_models.constants import (
    IncidentIgnoreReason,
    IncidentOrdering,
    IncidentPermission,
    IncidentSeverity,
    IncidentStatus,
    IncidentTag,
    IncidentValidity,
)
from .models import (
    Detail,
    Document,
    DocumentSchema,
    HealthCheckResponse,
    HoneytokenResponse,
    JWTResponse,
    JWTService,
    MultiScanResult,
    QuotaResponse,
    ScanResult,
    SecretScanPreferences,
    ServerMetadata,
)
from .sca_models import (
    ComputeSCAFilesResult,
    SCAScanAllOutput,
    SCAScanDiffOutput,
    SCAScanParameters,
)
from .utils.response import (
    is_create_ok,
    is_ok,
    load_detail,
    load_incident_response,
    load_no_content_response,
)
from .utils.tools import dict_filter_none, ensure_mutually_exclusive


logger = logging.getLogger(__name__)


# max files size to create a tar from
MAX_TAR_CONTENT_SIZE = 30 * 1024 * 1024


class ContentTooLarge(Exception):
    """
    Raised if the total size of files sent by the client exceeds MAX_TAR_CONTENT_SIZE
    """

    pass


class Versions:
    app_version: Optional[str] = None
    secrets_engine_version: Optional[str] = None


VERSIONS = Versions()


def _create_tar(root_path: Path, filenames: List[str]) -> bytes:
    """
    :param root_path: the root_path from which the tar is created
    :param files: the files which need to be added to the tar, filenames should be the paths relative to the root_path
    :return: a bytes object containing the tar.gz created from the files, with paths relative to root_path
    """
    tar_stream = BytesIO()
    current_dir_size = 0
    with tarfile.open(fileobj=tar_stream, mode="w:gz") as tar:
        for filename in filenames:
            full_path = root_path / filename
            current_dir_size += os.path.getsize(full_path)
            if current_dir_size > MAX_TAR_CONTENT_SIZE:
                raise ContentTooLarge(
                    f"The total size of the files processed exceeds {MAX_TAR_CONTENT_SIZE / (1024 * 1024):.0f}MB, "
                    f"please try again with less files"
                )
            tar.add(full_path, filename)
    return tar_stream.getvalue()


class GGClient:
    _version = "undefined"
    session: Session
    api_key: str
    base_uri: str
    timeout: Optional[float]
    user_agent: str
    extra_headers: Dict
    secret_scan_preferences: SecretScanPreferences

    def __init__(
        self,
        api_key: str,
        base_uri: Optional[str] = None,
        session: Optional[Session] = None,
        user_agent: Optional[str] = None,
        timeout: Optional[float] = DEFAULT_TIMEOUT,
    ):
        """
        :param api_key: API Key to be added to requests
        :param base_uri: Base URI for the API, defaults to "https://api.gitguardian.com"
        :param session: custom requests session, defaults to requests.Session()
        :param user_agent: user agent to identify requests, defaults to ""
        :param timeout: request timeout, defaults to 20s

        :raises ValueError: if the protocol or the api_key is invalid
        """

        if isinstance(base_uri, str):
            if not base_uri.startswith(("http://", "https://")):
                raise ValueError("Invalid protocol, prepend with http:// or https://")
        else:
            base_uri = DEFAULT_BASE_URI

        if not isinstance(api_key, str):
            raise TypeError("api_key is not a string")

        try:
            # The requests module encodes headers in latin-1, if api_key contains
            # characters which cannot be encoded in latin-1, the raised exception is
            # going to be very obscure. Catch the problem early to raise a clearer
            # exception.
            # See https://github.com/GitGuardian/ggshield/issues/101
            api_key.encode("latin-1")
        except UnicodeEncodeError:
            raise ValueError(
                "Invalid value for API Key: must be only latin-1 characters."
            )

        self.base_uri = base_uri
        self.api_key = api_key
        self.session = session if isinstance(session, Session) else Session()
        self.timeout = timeout
        self.user_agent = "pygitguardian/{} ({};py{})".format(
            self._version, platform.system(), platform.python_version()
        )

        if isinstance(user_agent, str):
            self.user_agent = " ".join([self.user_agent, user_agent])

        self.session.headers.update(
            {
                "User-Agent": self.user_agent,
                "Authorization": f"Token {api_key}",
            },
        )
        self.secret_scan_preferences = SecretScanPreferences()

    def request(
        self,
        method: str,
        endpoint: Optional[str] = None,
        version: Optional[str] = DEFAULT_API_VERSION,
        url: Optional[str] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        **kwargs: Any,
    ) -> Response:
        if endpoint is not None:
            _url = self._url_from_endpoint(endpoint, version)
        elif str is not None:
            _url = cast(str, url)
        else:
            raise ValueError("Request error: 'ednpoint' and 'url' cannot both be None")

        headers = (
            {**self.session.headers, **extra_headers}
            if extra_headers
            else self.session.headers
        )
        start = time.time()
        response: Response = self.session.request(
            method=method, url=_url, timeout=self.timeout, headers=headers, **kwargs
        )
        duration = time.time() - start
        logger.debug(
            "method=%s endpoint=%s status_code=%s duration=%f",
            method,
            endpoint,
            response.status_code,
            duration,
        )

        self.app_version = response.headers.get("X-App-Version", self.app_version)
        self.secrets_engine_version = response.headers.get(
            "X-Secrets-Engine-Version", self.secrets_engine_version
        )

        return response

    def _url_from_endpoint(self, endpoint: str, version: Optional[str]) -> str:
        if version:
            endpoint = urllib.parse.urljoin(version + "/", endpoint)

        return urllib.parse.urljoin(self.base_uri + "/", endpoint)

    @property
    def app_version(self) -> Optional[str]:
        global VERSIONS

        return VERSIONS.app_version

    @app_version.setter
    def app_version(self, value: Optional[str]) -> None:
        global VERSIONS

        VERSIONS.app_version = value

    @property
    def secrets_engine_version(self) -> Optional[str]:
        global VERSIONS

        return VERSIONS.secrets_engine_version

    @secrets_engine_version.setter
    def secrets_engine_version(self, value: Optional[str]) -> None:
        global VERSIONS

        VERSIONS.secrets_engine_version = value

    def get(
        self,
        endpoint: str,
        version: Optional[str] = DEFAULT_API_VERSION,
        extra_headers: Optional[Dict[str, str]] = None,
        **kwargs: Any,
    ) -> Response:
        return self.request(
            method="get",
            endpoint=endpoint,
            version=version,
            extra_headers=extra_headers,
            **kwargs,
        )

    def post(
        self,
        endpoint: str,
        data: Union[Dict[str, Any], List[Dict[str, Any]], None] = None,
        version: str = DEFAULT_API_VERSION,
        extra_headers: Optional[Dict[str, str]] = None,
        **kwargs: Any,
    ) -> Response:
        # Be aware that self.iac_directory_scan bypass this method and calls self.request directly.
        # self.iac_diff_scan also bypass this method
        return self.request(
            "post",
            endpoint=endpoint,
            json=data,
            version=version,
            extra_headers=extra_headers,
            **kwargs,
        )

    def patch(
        self,
        endpoint: str,
        data: Optional[Dict[str, str]] = None,
        version: str = DEFAULT_API_VERSION,
        extra_headers: Optional[Dict[str, str]] = None,
        **kwargs: Any,
    ) -> Response:
        return self.request(
            "patch",
            endpoint=endpoint,
            json=data,
            version=version,
            extra_headers=extra_headers,
            **kwargs,
        )

    def health_check(self) -> HealthCheckResponse:
        """
        health_check handles the /health endpoint of the API

        use Detail.status_code to check the response status code of the API

        200 if server is online and api_key is valid
        :return: Detail response and status code
        """
        resp = self.get(endpoint="health")

        return HealthCheckResponse(
            detail=load_detail(resp).detail,
            status_code=resp.status_code,
            app_version=self.app_version,
            secrets_engine_version=self.secrets_engine_version,
        )

    def content_scan(
        self,
        document: str,
        filename: Optional[str] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Union[Detail, ScanResult]:
        """
        content_scan handles the /scan endpoint of the API.

        If document contains `0` bytes, they will be replaced with the ASCII substitute
        character.

        :param filename: name of file, example: "intro.py"
        :param document: content of file
        :param extra_headers: additional headers to add to the request
        :return: Detail or ScanResult response and status code
        """

        doc_dict = {"document": document}
        if filename:
            doc_dict["filename"] = filename

        request_obj = cast(Dict[str, Any], Document.SCHEMA.load(doc_dict))
        DocumentSchema.validate_size(
            request_obj, self.secret_scan_preferences.maximum_document_size
        )

        resp = self.post(
            endpoint="scan",
            data=request_obj,
            extra_headers=extra_headers,
        )

        obj: Union[Detail, ScanResult]
        if is_ok(resp):
            obj = ScanResult.from_dict(resp.json())
        else:
            obj = load_detail(resp)

        obj.status_code = resp.status_code

        return obj

    def multi_content_scan(
        self,
        documents: List[Dict[str, str]],
        extra_headers: Optional[Dict[str, str]] = None,
        ignore_known_secrets: Optional[bool] = None,
    ) -> Union[Detail, MultiScanResult]:
        """
        multi_content_scan handles the /multiscan endpoint of the API.

        If documents contain `0` bytes, they will be replaced with the ASCII substitute
        character.

        :param documents: List of dictionaries containing the keys document
        and, optionally, filename.
            example: [{"document":"example content","filename":"intro.py"}]
        :param extra_headers: additional headers to add to the request
        :param ignore_known_secrets: indicates whether known secrets should be ignored
        :return: Detail or ScanResult response and status code
        """
        max_documents = self.secret_scan_preferences.maximum_documents_per_scan
        if len(documents) > max_documents:
            raise ValueError(
                f"too many documents submitted for scan (max={max_documents})"
            )

        if all(isinstance(doc, dict) for doc in documents):
            request_obj = cast(
                List[Dict[str, Any]], Document.SCHEMA.load(documents, many=True)
            )
        else:
            raise TypeError("each document must be a dict")

        for document in request_obj:
            DocumentSchema.validate_size(
                document, self.secret_scan_preferences.maximum_document_size
            )

        params = (
            {"ignore_known_secrets": ignore_known_secrets}
            if ignore_known_secrets
            else {}
        )
        resp = self.post(
            endpoint="multiscan",
            data=request_obj,
            extra_headers=extra_headers,
            params=params,
        )

        obj: Union[Detail, MultiScanResult]
        if is_ok(resp):
            obj = MultiScanResult.from_dict({"scan_results": resp.json()})
        else:
            obj = load_detail(resp)

        obj.status_code = resp.status_code

        return obj

    def quota_overview(
        self,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Union[Detail, QuotaResponse]:
        """
        quota_overview handles the /quotas endpoint of the API

        :param extra_headers: additional headers to add to the request
        :return: Detail or Quota response and status code
        """

        resp = self.get(
            endpoint="quotas",
            extra_headers=extra_headers,
        )

        obj: Union[Detail, QuotaResponse]
        if is_ok(resp):
            obj = QuotaResponse.from_dict(resp.json())
        else:
            obj = load_detail(resp)

        obj.status_code = resp.status_code

        return obj

    def create_honeytoken(
        self,
        name: Optional[str],
        type_: str,
        description: Optional[str],
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Union[Detail, HoneytokenResponse]:
        """
        Create a honeytoken via the /honeytokens endpoint of the API

        :param name: the honeytoken name
        :param type_: the honeytoken type
        :param description: the honeytoken description
        :param extra_headers: additional headers to add to the request
        :return: Detail or Honeytoken response and status code
        """
        try:
            resp = self.post(
                endpoint="honeytokens",
                extra_headers=extra_headers,
                data={
                    "name": name,
                    "type": type_,
                    "description": description,
                },
            )
        except requests.exceptions.ReadTimeout:
            result = Detail("The request timed out.")
            result.status_code = 504
        else:
            if is_create_ok(resp):
                result = HoneytokenResponse.from_dict(resp.json())
            else:
                result = load_detail(resp)
            result.status_code = resp.status_code
        return result

    def iac_directory_scan(
        self,
        directory: Path,
        filenames: List[str],
        scan_parameters: IaCScanParameters,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Union[Detail, IaCScanResult]:
        """
        iac_directory_scan handles the /iac_scan endpoint of the API.

        :param directory: path to the directory to scan
        :param filenames: filenames of the directory to include in the scan
        :param scan_parameters: minimum severities wanted and policies to ignore
            example: {"ignored_policies":["GG_IAC_0003"],"minimum_severity":"HIGH"}
        :param extra_headers: optional extra headers to add to the request
        :return: ScanResult response and status code
        """
        tar = _create_tar(directory, filenames)
        result: Union[Detail, IaCScanResult]
        try:
            # bypass self.post because data argument is needed in self.request and self.post use it as json
            resp = self.request(
                "post",
                endpoint="iac_scan",
                extra_headers=extra_headers,
                files={
                    "directory": tar,
                },
                data={
                    "scan_parameters": IaCScanParametersSchema().dumps(scan_parameters),
                },
            )
        except requests.exceptions.ReadTimeout:
            result = Detail("The request timed out.")
            result.status_code = 504
        else:
            if is_ok(resp):
                result = IaCScanResult.from_dict(resp.json())
            else:
                result = load_detail(resp)

            result.status_code = resp.status_code

        return result

    def iac_diff_scan(
        self,
        reference: bytes,
        current: bytes,
        scan_parameters: IaCScanParameters,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Union[Detail, IaCDiffScanResult]:
        """
        iac_diff_scan handles the /iac_diff_scan endpoint of the API.

        Scan two directories and compare their vulnerabilities.
        Vulnerabilities in reference but not in current are considered "new".
        Vulnerabilities in both reference and current are considered "unchanged".
        Vulnerabilities in current but not in reference are considered "deleted".

        :param reference: tar file containing the reference directory. Usually an incoming commit
        :param current: tar file of the current directory. Usually HEAD
        :param scan_parameters: minimum severities wanted and policies to ignore
            example: {"ignored_policies":["GG_IAC_0003"],"minimum_severity":"HIGH"}
        :param extra_headers: optional extra headers to add to the request
        :return: ScanResult response and status code
        """
        result: Union[Detail, IaCDiffScanResult]
        try:
            # bypass self.post because data argument is needed in self.request and self.post use it as json
            resp = self.request(
                "post",
                endpoint="iac_diff_scan",
                extra_headers=extra_headers,
                files={
                    "reference": reference,
                    "current": current,
                },
                data={
                    "scan_parameters": IaCScanParametersSchema().dumps(scan_parameters),
                },
            )
        except requests.exceptions.ReadTimeout:
            result = Detail("The request timed out.")
            result.status_code = 504
        else:
            if is_ok(resp):
                result = IaCDiffScanResult.from_dict(resp.json())
            else:
                result = load_detail(resp)

            result.status_code = resp.status_code
        return result

    def read_metadata(self) -> Optional[Detail]:
        """
        Fetch server preferences and store them in `self.secret_scan_preferences`.
        These preferences are then used by all future secret scans.

        Note that the call fails if the API key is not valid.

        :return: a Detail instance in case of error, None otherwise
        """
        resp = self.get("metadata")

        if not is_ok(resp):
            result = load_detail(resp)
            result.status_code = resp.status_code
            return result
        metadata = ServerMetadata.from_dict(resp.json())

        self.secret_scan_preferences = metadata.secret_scan_preferences
        return None

    def create_jwt(
        self,
        jwt_audience: str,
        service: JWTService,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Union[Detail, JWTResponse]:
        """
        Create a JWT token for other GitGuardian services.
        :return: Detail or JWT response and status code
        """

        resp = self.post(
            endpoint="auth/jwt",
            data={"audience": jwt_audience, "audience_type": service.value},
            extra_headers=extra_headers,
        )
        obj: Union[Detail, JWTResponse]
        if is_ok(resp):
            obj = JWTResponse.from_dict(resp.json())
        else:
            obj = load_detail(resp)
        obj.status_code = resp.status_code
        return obj

    def compute_sca_files(
        self,
        files: List[str],
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Union[Detail, ComputeSCAFilesResult]:
        if len(files) == 0:
            result = ComputeSCAFilesResult(sca_files=[])
            result.status_code = 200
            return result

        response = self.post(
            endpoint="sca/compute_sca_files/",
            data={"files": files},
            extra_headers=extra_headers,
        )
        result: Union[Detail, ComputeSCAFilesResult]
        if is_ok(response):
            result = ComputeSCAFilesResult.from_dict(response.json())
        else:
            result = load_detail(response)

        result.status_code = response.status_code
        return result

    def sca_scan_directory(
        self,
        tar_file: bytes,
        scan_parameters: SCAScanParameters,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Union[Detail, SCAScanAllOutput]:
        """
        Launches an SCA scan via SCA public API on a tar archive
        """

        result: Union[Detail, SCAScanAllOutput]

        try:
            # bypass self.post because data argument is needed in self.request and self.post use it as json
            response = self.request(
                "post",
                endpoint="sca/sca_scan_all/",
                files={"directory": tar_file},
                data={
                    "scan_parameters": SCAScanParameters.SCHEMA.dumps(scan_parameters)
                },
                extra_headers=extra_headers,
            )
        except requests.exceptions.ReadTimeout:
            result = Detail("The request timed out.")
            result.status_code = 504
        else:
            if is_ok(response):
                result = SCAScanAllOutput.from_dict(response.json())
            else:
                result = load_detail(response)

            result.status_code = response.status_code

        return result

    def scan_diff(
        self,
        reference: bytes,
        current: bytes,
        scan_parameters: SCAScanParameters,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Union[Detail, SCAScanDiffOutput]:
        result: Union[Detail, SCAScanDiffOutput]
        try:
            response = self.post(
                endpoint="sca/sca_scan_diff/",
                files={"reference": reference, "current": current},
                data={
                    "scan_parameters": SCAScanParameters.SCHEMA.dumps(scan_parameters)
                },
                extra_headers=extra_headers,
            )
        except requests.exceptions.ReadTimeout:
            result = Detail("The request timed out.")
            result.status_code = 504
        else:
            if is_ok(response):
                result = SCAScanDiffOutput.from_dict(response.json())
            else:
                result = load_detail(response)
            result.status_code = response.status_code
        return result

    # Incidents management
    def list_secret_incidents(
        self,
        per_page: Optional[int] = None,
        date_before: Optional[datetime] = None,
        date_after: Optional[datetime] = None,
        assignee_email: Optional[str] = None,
        assignee_id: Optional[int] = None,
        status: Optional[IncidentStatus] = None,
        severity: Optional[IncidentSeverity] = None,
        validity: Optional[IncidentValidity] = None,
        tags: Optional[List[IncidentTag]] = None,
        ordering: Optional[IncidentOrdering] = None,
        detector_group_name: Optional[str] = None,
        ignorer_id: Optional[int] = None,
        ignorer_api_token_id: Optional[str] = None,
        resolver_id: Optional[int] = None,
        resolver_api_token_id: Optional[str] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        _url: Optional[str] = None,
    ) -> Union[Detail, ListIncidentResult]:
        """
        List secret incidents detected by the GitGuardian dashboard.
        Occurrences are not returned by this method.
        """
        if _url is not None:
            resp = self.request(
                method="get",
                url=_url,
                extra_headers=extra_headers,
            )
        else:
            params = dict_filter_none(
                {
                    "per_page": per_page,
                    "date_before": date_before,
                    "date_after": date_after,
                    "assignee_email": assignee_email,
                    "assignee_id": assignee_id,
                    "status": status,
                    "severity": severity,
                    "validity": validity,
                    "tags": tags,
                    "ordering": ordering,
                    "detector_group_name": detector_group_name,
                    "ignorer_id": ignorer_id,
                    "ignorer_api_token_id": ignorer_api_token_id,
                    "resolver_id": resolver_id,
                    "resolver_api_token_id": resolver_api_token_id,
                }
            )

            resp = self.get(
                endpoint="incidents/secrets",
                extra_headers=extra_headers,
                params=params,
            )

        obj: Union[Detail, ListIncidentResult]
        if is_ok(resp):
            obj = ListIncidentResult.from_dict(
                {
                    "incidents": resp.json(),
                    "links": resp.links,
                }
            )
        else:
            obj = load_detail(resp)  # pragma: no cover

        obj.status_code = resp.status_code

        return obj

    def iter_incidents(self, **kwargs: Any) -> Generator[Incident, None, None]:
        page = self.list_secret_incidents(**kwargs)
        if "extra_headers" in kwargs:
            extra_headers = {"extra_headers": kwargs["extra_headers"]}
        else:
            extra_headers = {}
        while True:
            if isinstance(page, Detail):
                raise Exception(
                    "Received an error response before iteration completed."
                )
            if len(page.incidents) == 0:
                break
            yield from page.incidents
            if page.links is None:
                break  # pragma: no cover
            if page.links is not None and page.links.next is None:
                break
            if page.links is not None and page.links.next is not None:
                page = self.list_secret_incidents(
                    _url=page.links.next.url,
                    **extra_headers,
                )

    def get_secret_incident(
        self,
        incident_id: int,
        with_occurrences: Optional[int] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Union[Detail, Incident]:
        """
        Retrieve secret incident detected by the GitGuardian dashboard with or
        without its occurrences.
        """
        params = dict_filter_none({"with_occurrences": with_occurrences})
        return load_incident_response(
            self.get(
                endpoint=f"incidents/secrets/{int(incident_id)}",
                extra_headers=extra_headers,
                params=params,
            )
        )

    def update_incident_severity(
        self,
        incident_id: IncidentIdOrIncident,
        severity: IncidentSeverity,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Union[Detail, Incident]:
        """
        Set a secret incident's severity.
        """
        if isinstance(incident_id, Incident):
            incident_id = incident_id.id

        return load_incident_response(
            self.patch(
                endpoint=f"incidents/secrets/{int(incident_id)}",
                extra_headers=extra_headers,
                data={"severity": severity},
            )
        )

    def assign_incident(
        self,
        incident_id: IncidentIdOrIncident,
        email: Optional[str] = None,
        member_id: Optional[int] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Union[Detail, Incident]:
        """
        Assign s secret incident detected by the GitGuardian dashboard to a
        workspace member by email or member ID.
        """
        ensure_mutually_exclusive(
            "You must supply 'email' or 'member_id', but not both.",
            email,
            member_id,
        )

        return load_incident_response(
            self.post(
                endpoint=f"incidents/secrets/{int(incident_id)}/assign",
                extra_headers=extra_headers,
                params=dict_filter_none({"email": email, "member_id": member_id}),
            )
        )

    def unassign_incident(
        self,
        incident_id: IncidentIdOrIncident,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Union[Detail, Incident]:
        """
        Unassign a secret incident previously assigned to a workspace member.
        """
        return load_incident_response(
            self.post(
                endpoint=f"incidents/secrets/{int(incident_id)}/unassign",
                extra_headers=extra_headers,
            )
        )

    def resolve_incident(
        self,
        incident_id: IncidentIdOrIncident,
        secret_revoked: bool,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Union[Detail, Incident]:
        """
        Resolve a secret incident detected by the GitGuardian dashboard and
        specicy whether or not the secret was revoked.
        """
        return load_incident_response(
            self.post(
                endpoint=f"incidents/secrets/{int(incident_id)}/resolve",
                extra_headers=extra_headers,
                params={"secret_revoked": secret_revoked},
            )
        )

    def ignore_incident(
        self,
        incident_id: IncidentIdOrIncident,
        ignore_reason: IncidentIgnoreReason,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Union[Detail, Incident]:
        """
        Ignore a secret incident detected by the GitGuardian dashboard and
        specicy whether it is a test credential, a false positive or a low risk
        secret.
        """
        return load_incident_response(
            self.post(
                endpoint=f"incidents/secrets/{int(incident_id)}/ignore",
                extra_headers=extra_headers,
                params={"ignore_reason": ignore_reason},
            )
        )

    def reopen_incident(
        self,
        incident_id: IncidentIdOrIncident,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Union[Detail, Incident]:
        """
        Reopen a secret incident detected by the GitGuardian dashboard that was
        previously resolved or ignored.
        """
        return load_incident_response(
            self.post(
                endpoint=f"incidents/secrets/{int(incident_id)}/reopen",
                extra_headers=extra_headers,
            )
        )

    def share_incident(
        self,
        incident_id: IncidentIdOrIncident,
        auto_healing: Optional[bool] = None,
        feedback_collection: Optional[bool] = None,
        lifespan: Optional[int] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Union[Detail, SharedIncidentDetails]:
        """
        Share a secret incident by creating a public link that expires.
        Optionally, allow someone with the link to resolve/ignore the secret
        and/or leave feedback about the secret.
        """
        resp = self.post(
            endpoint=f"incidents/secrets/{int(incident_id)}/share",
            extra_headers=extra_headers,
            params=dict_filter_none(
                {
                    "auto_healing": auto_healing,
                    "feedback_collection": feedback_collection,
                    "lifespan": lifespan,
                }
            ),
        )

        obj: Union[Detail, SharedIncidentDetails]
        if is_ok(resp):
            obj = SharedIncidentDetails.from_dict(resp.json())
        else:  # pragma: no cover
            obj = load_detail(resp)

        obj.status_code = resp.status_code

        return obj

    def unshare_incident(
        self,
        incident_id: IncidentIdOrIncident,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Union[Detail, bool]:
        """
        Unshare a secret incident by revoking its public link before it
        expires.
        """
        return load_no_content_response(
            self.post(
                endpoint=f"incidents/secrets/{int(incident_id)}/unshare",
                extra_headers=extra_headers,
            )
        )

    def grant_access_to_incident(
        self,
        incident_id: IncidentIdOrIncident,
        incident_permission: IncidentPermission,
        email: Optional[str] = None,
        member_id: Optional[int] = None,
        invitation_id: Optional[int] = None,
        team_id: Optional[int] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Union[Detail, bool]:
        """
        Grant a user, an existing invitee or a team access to a secret
        incident.
        """
        ensure_mutually_exclusive(
            "'email', 'member_id', 'invitation_id' and 'team_id' "
            "are mutually exclusive--you can only provide one.",
            email,
            member_id,
            invitation_id,
            team_id,
        )

        return load_no_content_response(
            self.post(
                endpoint=f"incidents/secrets/{int(incident_id)}/grant_access",
                extra_headers=extra_headers,
                params=dict_filter_none(
                    {
                        "email": email,
                        "member_id": member_id,
                        "invitation_id": invitation_id,
                        "team_id": team_id,
                        "incident_permission": incident_permission,
                    }
                ),
            )
        )

    def revoke_access_to_incident(
        self,
        incident_id: IncidentIdOrIncident,
        email: Optional[str] = None,
        member_id: Optional[int] = None,
        invitation_id: Optional[int] = None,
        team_id: Optional[int] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Union[Detail, bool]:
        """
        Revoke access of a user, an existing invitee or a team to a secret
        incident.
        """
        ensure_mutually_exclusive(
            "'email', 'member_id', 'invitation_id' and 'team_id' "
            "are mutually exclusive--you can only provide one.",
            email,
            member_id,
            invitation_id,
            team_id,
        )

        return load_no_content_response(
            self.post(
                endpoint=f"incidents/secrets/{int(incident_id)}/revoke_access",
                extra_headers=extra_headers,
                params=dict_filter_none(
                    {
                        "email": email,
                        "member_id": member_id,
                        "invitation_id": invitation_id,
                        "team_id": team_id,
                    }
                ),
            )
        )
