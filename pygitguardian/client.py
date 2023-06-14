import logging
import os
import platform
import tarfile
import time
import urllib.parse
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, cast

import requests
from requests import Response, Session, codes

from .config import DEFAULT_API_VERSION, DEFAULT_BASE_URI, DEFAULT_TIMEOUT
from .iac_models import IaCScanParameters, IaCScanParametersSchema, IaCScanResult
from .models import (
    Detail,
    Document,
    DocumentSchema,
    HealthCheckResponse,
    HoneytokenResponse,
    MultiScanResult,
    QuotaResponse,
    ScanResult,
    SecretScanPreferences,
    ServerMetadata,
)


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


def load_detail(resp: Response) -> Detail:
    """
    load_detail loads a Detail from a response
    be it JSON or html.

    :param resp: API response
    :type resp: Response
    :return: detail object of response
    :rtype: Detail
    """
    if resp.headers["content-type"] == "application/json":
        data = resp.json()
    else:
        data = {"detail": resp.text}

    return Detail.from_dict(data)


def is_ok(resp: Response) -> bool:
    """
    is_ok returns True is the API responded with 200
    and the content type is JSON.
    """
    return (
        resp.headers["content-type"] == "application/json"
        and resp.status_code == codes.ok
    )


def is_create_ok(resp: Response) -> bool:
    """
    is_create_ok returns True if the API returns code 201
    and the content type is JSON.
    """
    return (
        resp.headers["content-type"] == "application/json"
        and resp.status_code == codes.created
    )


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
        endpoint: str,
        version: Optional[str] = DEFAULT_API_VERSION,
        extra_headers: Optional[Dict[str, str]] = None,
        **kwargs: Any,
    ) -> Response:
        url = self._url_from_endpoint(endpoint, version)

        headers = (
            {**self.session.headers, **extra_headers}
            if extra_headers
            else self.session.headers
        )
        start = time.time()
        response: Response = self.session.request(
            method=method, url=url, timeout=self.timeout, headers=headers, **kwargs
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
        return self.request(
            "post",
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

        If document contains `0` bytes, they will be replaced with the Unicode
        replacement character.

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

        If documents contain `0` bytes, they will be replaced with the Unicode
        replacement character.

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

    # For IaC Scans
    def iac_directory_scan(
        self,
        directory: Path,
        filenames: List[str],
        scan_parameters: IaCScanParameters,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Union[Detail, IaCScanResult]:
        tar = _create_tar(directory, filenames)
        result: Union[Detail, IaCScanResult]
        try:
            resp = self.post(
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
