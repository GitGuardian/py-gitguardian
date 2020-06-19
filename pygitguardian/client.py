import platform
import urllib.parse
from typing import Dict, List, Optional, Union

import requests
from requests import Response, Session, codes

from .config import (
    DEFAULT_API_VERSION,
    DEFAULT_BASE_URI,
    DEFAULT_TIMEOUT,
    MULTI_DOCUMENT_LIMIT,
)
from .models import Detail, Document, MultiScanResult, ScanResult


class GGClient:
    _version = "undefined"

    def __init__(
        self,
        api_key: str,
        base_uri: Optional[str] = None,
        session: Optional[requests.Session] = None,
        user_agent: Optional[str] = None,
        timeout: Optional[float] = DEFAULT_TIMEOUT,
    ):
        """
        :param api_key: API Key to be added to requests
        :param base_uri: Base URI for the API, defaults to "https://api.gitguardian.com"
        :param session: custom requests session, defaults to requests.Session()
        :param user_agent: user agent to identify requests, defaults to ""
        :param timeout: request timeout, defaults to 20s

        :raises ValueError: if the protocol is invalid
        """

        if base_uri:
            if not base_uri.startswith(("http://", "https://")):
                raise ValueError("Invalid protocol, prepend with http:// or https://")
        else:
            base_uri = DEFAULT_BASE_URI

        if not isinstance(api_key, str):
            raise TypeError("api_key is not a string")

        self.base_uri = base_uri
        self.api_key = api_key
        self.session = (
            session if session is isinstance(session, Session) else requests.Session()
        )
        self.timeout = timeout
        self.user_agent = "pygitguardian/{0} ({1};py{2})".format(
            self._version, platform.system(), platform.python_version()
        )

        if user_agent:
            self.user_agent = " ".join([self.user_agent, user_agent])

        self.session.headers.update(
            {
                "User-Agent": self.user_agent,
                "Authorization": "Token {0}".format(api_key),
            }
        )

    def request(
        self,
        method: str,
        endpoint: str,
        version: Optional[str] = DEFAULT_API_VERSION,
        **kwargs
    ) -> Response:
        if version:
            endpoint = urllib.parse.urljoin(version + "/", endpoint)

        url = urllib.parse.urljoin(self.base_uri, endpoint)

        resp = self.session.request(
            method=method, url=url, timeout=self.timeout, **kwargs
        )

        if resp.headers["content-type"] != "application/json":
            raise TypeError("Response is not JSON")

        return resp

    def post(
        self,
        endpoint: str,
        data: str = None,
        version: str = DEFAULT_API_VERSION,
        **kwargs
    ) -> Response:
        return self.request(
            "post", endpoint=endpoint, json=data, version=version, **kwargs,
        )

    def get(
        self, endpoint: str, version: Optional[str] = DEFAULT_API_VERSION, **kwargs
    ) -> Response:
        return self.request(method="get", endpoint=endpoint, version=version, **kwargs)

    def health_check(self) -> Detail:
        """
        health_check handles the /health endpoint of the API

        use Detail.status_code to check the response status code of the API

        200 if server is online and api_key is valid
        :return: Detail response and status code
        """
        resp = self.get(endpoint="health")

        obj = Detail.SCHEMA.load(resp.json())
        obj.status_code = resp.status_code

        return obj

    def content_scan(
        self, document: str, filename: Optional[str] = None
    ) -> Union[Detail, ScanResult]:
        """
        content_scan handles the /scan endpoint of the API

        :param filename: name of file, example: "intro.py"
        :param document: content of file
        :return: Detail or ScanResult response and status code
        """

        doc_dict = {"document": document}
        if filename:
            doc_dict["filename"] = filename

        request_obj = Document.SCHEMA.load(doc_dict)

        resp = self.post(endpoint="scan", data=request_obj)
        if resp.status_code == codes.ok:
            obj = ScanResult.SCHEMA.load(resp.json())
        else:
            obj = Detail.SCHEMA.load(resp.json())

        obj.status_code = resp.status_code

        return obj

    def multi_content_scan(
        self, documents: List[Dict[str, str]],
    ) -> Union[Detail, MultiScanResult]:
        """
        multi_content_scan handles the /multiscan endpoint of the API

        :param documents: List of dictionaries containing the keys document
        and, optionally, filename.
            example: [{"document":"example content","filename":"intro.py"}]
        :return: Detail or ScanResult response and status code
        """
        if len(documents) > MULTI_DOCUMENT_LIMIT:
            raise ValueError(
                "too many documents submitted for scan (max={0})".format(
                    MULTI_DOCUMENT_LIMIT
                )
            )

        if all(isinstance(doc, dict) for doc in documents):
            request_obj = Document.SCHEMA.load(documents, many=True)
        else:
            raise TypeError("each document must be a dict")

        resp = self.post(endpoint="multiscan", data=request_obj)

        if resp.status_code == codes.ok:
            obj = MultiScanResult.SCHEMA.load(dict(scan_results=resp.json()))
        else:
            obj = Detail.SCHEMA.load(resp.json())

        obj.status_code = resp.status_code

        return obj
