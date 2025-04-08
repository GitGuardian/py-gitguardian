# pyright: reportIncompatibleVariableOverride=false
# Disable this check because of multiple non-dangerous violations (SCHEMA variables,
# BaseSchema.Meta class)
from dataclasses import dataclass, field
from datetime import date, datetime
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Type, cast
from uuid import UUID

import marshmallow_dataclass
from marshmallow import (
    ValidationError,
    fields,
    post_dump,
    post_load,
    pre_load,
    validate,
)

from .config import (
    DEFAULT_PRE_COMMIT_MESSAGE,
    DEFAULT_PRE_PUSH_MESSAGE,
    DEFAULT_PRE_RECEIVE_MESSAGE,
    DOCUMENT_SIZE_THRESHOLD_BYTES,
    MULTI_DOCUMENT_LIMIT,
)
from .models_utils import (
    Base,
    BaseSchema,
    FromDictMixin,
    FromDictWithBase,
    PaginationParameter,
    SearchParameter,
    ToDictMixin,
)


class DocumentSchema(BaseSchema):
    filename = fields.String(validate=validate.Length(max=256), allow_none=True)
    document = fields.String(required=True)

    @staticmethod
    def validate_size(document: Dict[str, Any], maximum_size: int) -> None:
        """Raises a ValidationError if the content of the document is longer than
        `maximum_size`.

        This is not implemented as a Marshmallow validator because the maximum size can
        vary.
        """
        encoded = document["document"].encode("utf-8", errors="replace")
        if len(encoded) > maximum_size:
            raise ValidationError(
                f"file exceeds the maximum allowed size of {maximum_size}B"
            )

    @post_load
    def replace_0_bytes(self, in_data: Dict[str, Any], **kwargs: Any) -> Dict[str, Any]:
        doc = in_data["document"]
        # Our API does not accept 0 bytes in documents so replace them with
        # the ASCII substitute character.
        # We no longer uses the Unicode replacement character (U+FFFD) because
        # it makes the encoded string one byte longer, making it possible to
        # hit the maximum size limit.
        in_data["document"] = doc.replace("\0", "\x1a")
        return in_data

    @post_load
    def force_utf_8_encoding(
        self, in_data: Dict[str, Any], **kwargs: Any
    ) -> Dict[str, Any]:
        doc = in_data["document"]
        # Force UTF-8 and substitute ? for encoding errors
        in_data["document"] = doc.encode("utf-8", errors="replace").decode("utf-8")
        return in_data


class Document(Base):
    """
    Document is a request object for communicating documents
    to the API

    Attributes:
        filename (optional,str): filename for filename evaluation
        document (str): text content
    """

    SCHEMA = DocumentSchema()

    def __init__(self, document: str, filename: Optional[str] = None, **kwargs: Any):
        super().__init__()
        self.document = document
        if filename:
            self.filename = filename

    def __repr__(self) -> str:
        return f"filename:{self.filename}, document:{self.document}"


class DetailSchema(BaseSchema):
    detail = fields.String(required=True)

    @pre_load
    def rename_errors(
        self, data: Dict[str, Any], many: bool, **kwargs: Any
    ) -> Dict[str, Any]:
        error = data.pop("error", None)
        if error is not None:
            data["detail"] = str(error)

        return data

    @post_load
    def make_detail_response(self, data: Dict[str, Any], **kwargs: Any) -> "Detail":
        return Detail(**data)


class Detail(FromDictWithBase):
    """Detail is a response object mostly returned on error or when the
    api output is a simple string.

    Attributes:
        detail (str): response string
    """

    SCHEMA = DetailSchema()

    def __init__(
        self, detail: str, status_code: Optional[int] = None, **kwargs: Any
    ) -> None:
        super().__init__(status_code=status_code)
        self.detail = detail

    def __repr__(self) -> str:
        return f"{self.status_code}:{self.detail}"


class MatchSchema(BaseSchema):
    match = fields.String(required=True)
    match_type = fields.String(data_key="type", required=True)
    line_start = fields.Int(allow_none=True)
    line_end = fields.Int(allow_none=True)
    index_start = fields.Int(allow_none=True)
    index_end = fields.Int(allow_none=True)

    @post_load
    def make_match(self, data: Dict[str, Any], **kwargs: Any) -> "Match":
        return Match(**data)


class Match(FromDictWithBase):
    """
    Match describes an issue found by GitGuardian.

    Fields:

    - match: the matched string

    - match_type: the "label" of the matched string ("username", "password"...)

    - index_start: 0-based index of the first character of the match inside the
      document.

    - index_end: 0-based index of the last character of the match inside the
      document (not the index of the character after the last character!)

    - line_start: 1-based index of the line where the first character of the
      match is.

    - line_end: 1-based index of the line where the last character of the
      match is.
    """

    SCHEMA = MatchSchema()

    def __init__(
        self,
        match: str,
        match_type: str,
        line_start: Optional[int] = None,
        line_end: Optional[int] = None,
        index_start: Optional[int] = None,
        index_end: Optional[int] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__()
        self.match = match
        self.match_type = match_type
        self.line_start = line_start
        self.line_end = line_end
        self.index_start = index_start
        self.index_end = index_end

    def __repr__(self) -> str:
        return (
            "match:{}, "
            "match_type:{}, "
            "line_start:{}, "
            "line_end:{}, "
            "index_start:{}, "
            "index_end:{}".format(
                self.match,
                self.match_type,
                repr(self.line_start),
                repr(self.line_end),
                repr(self.index_start),
                repr(self.index_end),
            )
        )


class DiffKind(str, Enum):
    ADDITION = "addition"
    DELETION = "deletion"
    CONTEXT = "context"


class PolicyBreakSchema(BaseSchema):
    break_type = fields.String(data_key="type", required=True)
    policy = fields.String(required=True)
    validity = fields.String(required=False, load_default=None, dump_default=None)
    known_secret = fields.Boolean(required=False, load_default=False, dump_default=None)
    incident_url = fields.String(required=False, load_default=None, dump_default=None)
    matches = fields.List(fields.Nested(MatchSchema), required=True)
    is_excluded = fields.Boolean(required=False, load_default=False, dump_default=False)
    exclude_reason = fields.String(required=False, load_default=None, dump_default=None)
    diff_kind = fields.Enum(
        DiffKind, by_value=True, required=False, load_default=None, dump_default=None
    )

    @post_load
    def make_policy_break(self, data: Dict[str, Any], **kwargs: Any) -> "PolicyBreak":
        return PolicyBreak(**data)


class PolicyBreak(FromDictWithBase):
    """
    PolicyBreak describes a GitGuardian policy break found
    in a scan.
    A PolicyBreak can contain multiple matches, for example,
    on secrets that have a client id and client secret.
    """

    SCHEMA = PolicyBreakSchema()

    def __init__(
        self,
        break_type: str,
        policy: str,
        validity: str,
        matches: List[Match],
        known_secret: bool = False,
        incident_url: Optional[str] = None,
        is_excluded: bool = False,
        exclude_reason: Optional[str] = None,
        diff_kind: Optional[DiffKind] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__()
        self.break_type = break_type
        self.policy = policy
        self.validity = validity
        self.known_secret = known_secret
        self.incident_url = incident_url
        self.matches = matches
        self.is_excluded = is_excluded
        self.exclude_reason = exclude_reason
        self.diff_kind = diff_kind

    @property
    def is_secret(self) -> bool:
        return self.policy == "Secrets detection"

    def __repr__(self) -> str:
        return (
            "break_type:{}, "
            "policy:{}, "
            "matches: {}".format(self.break_type, self.policy, repr(self.matches))
        )


class ScanResultSchema(BaseSchema):
    policy_break_count = fields.Integer(required=True)
    policies = fields.List(fields.String(), required=True)
    policy_breaks = fields.List(fields.Nested(PolicyBreakSchema), required=True)
    is_diff = fields.Boolean(required=False, load_default=False, dump_default=None)

    @post_load
    def make_scan_result(self, data: Dict[str, Any], **kwargs: Any) -> "ScanResult":
        return ScanResult(**data)


class ScanResult(FromDictWithBase):
    """ScanResult is a response object returned on a Content Scan

    Attributes:
        status_code (int): response status code
        policy_break_count (int): number of policy breaks
        policy_breaks (List): policy break list
        policies (List[str]): string list of policies evaluated
    """

    SCHEMA = ScanResultSchema()

    def __init__(
        self,
        policy_break_count: int,
        policy_breaks: List[PolicyBreak],
        policies: List[str],
        is_diff: bool = False,
        **kwargs: Any,
    ) -> None:
        """
        :param policy_break_count: number of policy breaks
        :type policy_break_count: int
        :param policy_breaks: policy break list
        :type policy_breaks: List
        :param policies: string list of policies evaluated
        :type policies: List[str]
        :param is_diff: true if the document scanned is a diff
        :type is_diff: bool
        """
        super().__init__()
        self.policy_break_count = policy_break_count
        self.policies = policies
        self.policy_breaks = policy_breaks
        self.is_diff = is_diff

    @property
    def has_policy_breaks(self) -> bool:
        """has_secrets is an easy way to check if your provided document has policy breaks

        >>> obj = ScanResult(2, [], [])
        >>> obj.has_policy_breaks
        True

        :return: true if there were policy breaks (including secrets) in the document
        :rtype: bool
        """

        return self.policy_break_count > 0

    @property
    def has_secrets(self) -> bool:
        """has_secrets is an easy way to check if your provided document has secrets

        :return: true if there were secrets in the document
        :rtype: bool
        """

        return any(policy_break.is_secret for policy_break in self.policy_breaks)

    def __repr__(self) -> str:
        return (
            "policy_break_count:{}, "
            "policies:{}, "
            "policy_breaks: {}".format(
                self.policy_break_count, self.policies, self.policy_breaks
            )
        )

    def __str__(self) -> str:
        return "{} policy breaks from the evaluated policies: {}".format(
            self.policy_break_count,
            ", ".join(policy_break.policy for policy_break in self.policy_breaks),
        )


class MultiScanResultSchema(BaseSchema):
    scan_results = fields.List(
        fields.Nested(ScanResultSchema),
        required=True,
        validate=validate.Length(min=1),
    )

    @post_load
    def make_scan_result(
        self, data: Dict[str, Any], **kwargs: Any
    ) -> "MultiScanResult":
        return MultiScanResult(**data)


class MultiScanResult(FromDictWithBase):
    """ScanResult is a response object returned on a Content Scan

    Attributes:
        status_code (int): response status code
        policy_break_count (int): number of policy breaks
        policy_breaks (List): policy break list
        policies (List[str]): string list of policies evaluated
    """

    SCHEMA = MultiScanResultSchema()

    def __init__(self, scan_results: List[ScanResult], **kwargs: Any) -> None:
        """
        :param scan_results: List of scan_results
        """
        super().__init__()
        self.scan_results = scan_results

    @property
    def has_policy_breaks(self) -> bool:
        """has_policy_breaks is an easy way to check if your provided document has policy breaks

        >>> obj = ScanResult(2, [], [])
        >>> obj.has_policy_breaks
        True

        :return: true if there were policy breaks (including secrets) in the documents
        :rtype: bool
        """

        return any(scan_result.has_policy_breaks for scan_result in self.scan_results)

    @property
    def has_secrets(self) -> bool:
        """has_secrets is an easy way to check if your provided document has secrets

        :return: true if there were secrets in the documents
        :rtype: bool
        """

        return any(scan_result.has_secrets for scan_result in self.scan_results)

    def __repr__(self) -> str:
        return f"scan_results:{self.scan_results}"

    def __str__(self) -> str:
        return "{} scan results containing {} policy breaks".format(
            len(self.scan_results),
            len(
                [
                    policy_break
                    for scan_result in self.scan_results
                    for policy_break in scan_result.policy_breaks
                ]
            ),
        )


class QuotaSchema(BaseSchema):
    count = fields.Int()
    limit = fields.Int()
    remaining = fields.Int()
    since = fields.Date()

    @post_load
    def make_quota(self, data: Dict[str, Any], **kwargs: Any) -> "Quota":
        return Quota(**data)


class Quota(Base, FromDictMixin):
    """
    Quota describes a quota category in the GitGuardian API.
    Allows you to check your current available quota.
    Example:
    {"count": 2,
    "limit": 5000,
    "remaining": 4998,
    "since": "2021-04-18"}
    """

    SCHEMA = QuotaSchema()

    def __init__(
        self, count: int, limit: int, remaining: int, since: date, **kwargs: Any
    ) -> None:
        super().__init__()
        self.count = count
        self.limit = limit
        self.remaining = remaining
        self.since = since

    def __repr__(self) -> str:
        return (
            "count:{}, "
            "limit:{}, "
            "remaining:{}, "
            "since:{}".format(
                self.count, self.limit, self.remaining, self.since.isoformat()
            )
        )


class QuotaResponseSchema(BaseSchema):
    content = fields.Nested(QuotaSchema)

    @post_load
    def make_quota_response(
        self, data: Dict[str, Any], **kwargs: Any
    ) -> "QuotaResponse":
        return QuotaResponse(**data)


class QuotaResponse(Base, FromDictMixin):
    """
    Quota describes a quota category in the GitGuardian API.
    Allows you to check your current available quota.
    Example:
    {"content": {
        "count": 2,
        "limit": 5000,
        "remaining": 4998,
        "since": "2021-04-18"}}
    """

    SCHEMA = QuotaResponseSchema()

    def __init__(self, content: Quota, **kwargs: Any) -> None:
        super().__init__()
        self.content = content

    def __repr__(self) -> str:
        return f"content:{repr(self.content)}"


class HoneytokenResponseSchema(BaseSchema):
    id = fields.UUID()
    name = fields.String()
    description = fields.String(allow_none=True)
    created_at = fields.AwareDateTime()
    gitguardian_url = fields.URL()
    status = fields.String()
    triggered_at = fields.AwareDateTime(allow_none=True)
    revoked_at = fields.AwareDateTime(allow_none=True)
    open_events_count = fields.Int(allow_none=True)
    type_ = fields.String(data_key="type")
    creator_id = fields.Int(allow_none=True)
    revoker_id = fields.Int(allow_none=True)
    creator_api_token_id = fields.String(allow_none=True)
    revoker_api_token_id = fields.String(allow_none=True)
    token = fields.Mapping(fields.String(), fields.String())
    tags = fields.List(fields.String())

    @post_load
    def make_honeytoken_response(
        self, data: Dict[str, Any], **kwargs: Any
    ) -> "HoneytokenResponse":
        return HoneytokenResponse(**data)


class HoneytokenResponse(Base, FromDictMixin):
    """
    honeytoken creation in the GitGuardian API.
    Allows users to create and get a honeytoken.
    Example:
        {
            "id": "d45a123f-b15d-4fea-abf6-ff2a8479de5b",
            "name": "honeytoken A",
            "description": "honeytoken used in the repository AA",
            "created_at": "2019-08-22T14:15:22Z",
            "gitguardian_url":
                "https://dashboard.gitguardian.com/workspace/1/honeytokens/d45a123f-b15d-4fea-abf6-ff2a8479de5b",
            "status": "active",
            "triggered_at": "2019-08-22T14:15:22Z",
            "revoked_at": "2019-08-22T14:15:22Z",
            "open_events_count": 122,
            "type": "AWS",
            "creator_id": 122,
            "revoker_id": 122,
            "creator_api_token_id": null,
            "revoker_api_token_id": null,
            "token": {
                "access_token_id": "AAAA",
                "secret_key": "BBB"
            },
        "tags": ["publicly_exposed"]
        }
    """

    SCHEMA = HoneytokenResponseSchema()

    def __init__(
        self,
        id: UUID,
        name: str,
        description: Optional[str],
        created_at: datetime,
        gitguardian_url: str,
        status: str,
        triggered_at: Optional[datetime],
        revoked_at: Optional[datetime],
        open_events_count: Optional[int],
        type_: str,
        creator_id: Optional[int],
        revoker_id: Optional[int],
        creator_api_token_id: Optional[str],
        revoker_api_token_id: Optional[str],
        token: Dict[str, str],
        tags: List[str],
        **kwargs: Any,
    ) -> None:
        super().__init__()
        self.id = id
        self.name = name
        self.description = description
        self.created_at = created_at
        self.gitguardian_url = gitguardian_url
        self.status = status
        self.triggered_at = triggered_at
        self.revoked_at = revoked_at
        self.open_events_count = open_events_count
        self.type_ = type_
        self.creator_id = creator_id
        self.revoker_id = revoker_id
        self.creator_api_token_id = creator_api_token_id
        self.revoker_api_token_id = revoker_api_token_id
        self.token = token
        self.tags = tags

    def __repr__(self) -> str:
        return f"honeytoken:{self.id} {self.name}"


class HoneytokenWithContextResponseSchema(BaseSchema):
    content = fields.String()
    filename = fields.String()
    language = fields.String()
    suggested_commit_message = fields.String()
    honeytoken_id = fields.UUID()
    gitguardian_url = fields.URL()

    @post_load
    def make_honeytoken_with_context_response(
        self, data: Dict[str, Any], **kwargs: Any
    ) -> "HoneytokenWithContextResponse":
        return HoneytokenWithContextResponse(**data)


class HoneytokenWithContextResponse(Base, FromDictMixin):
    """
    honeytoken creation with context in the GitGuardian API.
    Allows users to get a file where a new honeytoken is.
    Example:
        {
            "content": "def return_aws_credentials():\n \
                            aws_access_key_id = XXXXXXXX\n \
                            aws_secret_access_key = XXXXXXXX\n \
                            aws_region = us-west-2",\n \
                            return (aws_access_key_id, aws_secret_access_key, aws_region)\n",
            "filename": "aws.py",
            "language": "python",
            "suggested_commit_message": "Add AWS credentials",
            "honeytoken_id": "d45a123f-b15d-4fea-abf6-ff2a8479de5b",
            "gitguardian_url":
                "https://dashboard.gitguardian.com/workspace/1/honeytokens/d45a123f-b15d-4fea-abf6-ff2a8479de5b",
        }
    """

    SCHEMA = HoneytokenWithContextResponseSchema()

    def __init__(
        self,
        content: str,
        filename: str,
        language: str,
        suggested_commit_message: str,
        honeytoken_id: UUID,
        gitguardian_url: str,
        **kwargs: Any,
    ) -> None:
        super().__init__()
        self.content = content
        self.filename = filename
        self.language = language
        self.suggested_commit_message = suggested_commit_message
        self.honeytoken_id = honeytoken_id
        self.gitguardian_url = gitguardian_url

    def __repr__(self) -> str:
        return f"honeytoken_context:{self.filename}"


class HealthCheckResponseSchema(BaseSchema):
    detail = fields.String(allow_none=False)
    status_code = fields.Int(allow_none=False)
    app_version = fields.String(allow_none=True)
    secrets_engine_version = fields.String(allow_none=True)


class HealthCheckResponse(Base):
    SCHEMA = HealthCheckResponseSchema()

    def __init__(
        self,
        detail: str,
        status_code: int,
        app_version: Optional[str] = None,
        secrets_engine_version: Optional[str] = None,
        **kwargs: Any,
    ):
        super().__init__()
        self.detail = detail
        self.status_code = status_code
        self.app_version = app_version
        self.secrets_engine_version = secrets_engine_version

    def __repr__(self) -> str:
        return (
            "detail:{}, "
            "status_code:{}, "
            "app version:{}, "
            "secrets engine version:{}".format(
                self.detail,
                self.status_code,
                self.app_version or "",
                self.secrets_engine_version or "",
            )
        )


class DetectorType(str, Enum):
    SPECIFIC = "specific"
    GENERIC = "generic"
    CUSTOM = "custom"


class DetectorDetailsSchema(BaseSchema):
    name = fields.String(required=True)
    display_name = fields.String(required=True)
    type = fields.Enum(DetectorType, by_value=True, required=True)
    category = fields.String(required=True)
    is_active = fields.Boolean(required=True)
    scans_code_only = fields.Boolean(required=True)
    checkable = fields.Boolean(required=True)
    use_with_validity_check_disabled = fields.Boolean(required=True)
    frequency = fields.Float(required=True)
    removed_at = fields.String(required=False, load_default=None, dump_default=None)
    open_incidents_count = fields.Int(required=True)
    ignored_incidents_count = fields.Int(required=True)
    resolved_incidents_count = fields.Int(required=True)

    @post_load
    def make_detector(self, data: Dict[str, Any], **kwargs: Any) -> "DetectorDetails":
        return DetectorDetails(**data)


class DetectorDetails(Base, FromDictMixin):
    """ "
    Response from /v1/detectors, to retrieve a detetor details
    from the API
    {
        "name": "aws_iam",
        "display_name": "AWS Keys",
        "type": "specific",
        "category": "Cloud Provider",
        "is_active": true,
        "scans_code_only": false,
        "checkable": true,
        "use_with_validity_check_disabled": true,
        "frequency": "1O3.74",
        "removed_at": null,
        "open_incidents_count": 17,
        "ignored_incidents_count": 9,
        "resolved_incidents_count": 42
    }
    """

    SCHEMA = DetectorDetailsSchema()

    def __init__(
        self,
        name: str,
        display_name: str,
        type: DetectorType,
        category: str,
        is_active: bool,
        scans_code_only: bool,
        checkable: bool,
        use_with_validity_check_disabled: bool,
        frequency: float,
        removed_at: str | None,
        open_incidents_count: int,
        ignored_incidents_count: int,
        resolved_incidents_count: int,
        **kwargs: Any,
    ):
        super().__init__()
        self.name = name
        self.display_name = display_name
        self.type = type
        self.category = category
        self.is_active = is_active
        self.scans_code_only = scans_code_only
        self.checkable = checkable
        self.use_with_validity_check_disabled = use_with_validity_check_disabled
        self.frequency = frequency
        self.removed_at = removed_at
        self.open_incidents_count = open_incidents_count
        self.ignored_incidents_count = ignored_incidents_count
        self.resolved_incidents_count = resolved_incidents_count


class DetectorDetailsResponseSchema(BaseSchema):
    name = fields.String(required=True)
    display_name = fields.String(required=True)
    type = fields.Enum(DetectorType, by_value=True, required=True)
    category = fields.String(required=True)
    is_active = fields.Boolean(required=True)
    scans_code_only = fields.Boolean(required=True)
    checkable = fields.Boolean(required=True)
    use_with_validity_check_disabled = fields.Boolean(required=True)
    frequency = fields.Float(required=True)
    removed_at = fields.String(required=False, load_default=None, dump_default=None)
    open_incidents_count = fields.Int(required=True)
    ignored_incidents_count = fields.Int(required=True)
    resolved_incidents_count = fields.Int(required=True)

    @post_load
    def make_detector(self, data: Dict[str, Any], **kwargs: Any) -> "DetectorDetails":
        return DetectorDetails(**data)


class DetectorDetailsResponse(Base, FromDictMixin):
    SCHEMA = DetectorDetailsResponseSchema()

    def __init__(self, detector: DetectorDetails, **kwargs: Any):
        super().__init__()
        self.name = detector.name
        self.display_name = detector.display_name
        self.type = detector.type
        self.category = detector.category
        self.is_active = detector.is_active
        self.scans_code_only = detector.scans_code_only
        self.checkable = detector.checkable
        self.use_with_validity_check_disabled = (
            detector.use_with_validity_check_disabled
        )
        self.frequency = detector.frequency
        self.removed_at = detector.removed_at
        self.open_incidents_count = detector.open_incidents_count
        self.ignored_incidents_count = detector.ignored_incidents_count
        self.resolved_incidents_count = detector.resolved_incidents_count

    def __repr__(self) -> str:
        return (
            f"name:{self.name}, "
            f"display_name:{self.display_name}, "
            f"type:{self.type}, "
            f"category:{self.category}, "
            f"is_active:{self.is_active}, "
            f"scans_code_only:{self.scans_code_only}, "
            f"checkable:{self.checkable}, "
            f"use_with_validity_check_disabled:{self.use_with_validity_check_disabled}, "
            f"frequency:{self.frequency}, "
            f"removed_at:{self.removed_at}, "
            f"open_incidents_count:{self.open_incidents_count}, "
            f"ignored_incidents_count:{self.ignored_incidents_count}, "
            f"resolved_incidents_count:{self.resolved_incidents_count}"
        )


class TokenType(str, Enum):
    PERSONAL_ACCESS_TOKEN = "personal_access_token"
    SERVICE_ACCOUNT = "service_account"


class TokenStatus(str, Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class TokenScope(str, Enum):
    SCAN = "scan"
    INCIDENTS_READ = "incidents:read"
    INCIDENTS_WRITE = "incidents:write"
    INCIDENTS_SHARE = "incidents:share"
    MEMBERS_READ = "members:read"
    MEMBERS_WRITE = "members:write"
    TEAMS_READ = "teams:read"
    TEAMS_WRITE = "teams:write"
    AUDIT_LOGS_READ = "audit_logs:read"
    HONEYTOKENS_READ = "honeytokens:read"
    HONEYTOKENS_WRITE = "honeytokens:write"
    API_TOKENS_READ = "api_tokens:read"
    API_TOKENS_WRITE = "api_tokens:write"
    IP_ALLOWLIST_READ = "ip_allowlist:read"
    IP_ALLOWLIST_WRITE = "ip_allowlist:write"
    SOURCES_READ = "sources:read"
    SOURCES_WRITE = "sources:write"
    NHI_WRITE = "nhi:write"


class APITokensResponseSchema(BaseSchema):
    id = fields.UUID(required=True)
    name = fields.String(required=True)
    workspace_id = fields.Int(required=True)
    type = fields.Enum(TokenType, by_value=True, required=True)
    status = fields.Enum(TokenStatus, by_value=True, required=True)
    created_at = fields.AwareDateTime(required=True)
    last_used_at = fields.AwareDateTime(allow_none=True)
    expire_at = fields.AwareDateTime(allow_none=True)
    revoked_at = fields.AwareDateTime(allow_none=True)
    member_id = fields.Int(allow_none=True)
    creator_id = fields.Int(allow_none=True)
    scopes = fields.List(fields.Enum(TokenScope, by_value=True), required=False)

    @post_load
    def make_api_tokens_response(
        self, data: Dict[str, Any], **kwargs: Any
    ) -> "APITokensResponse":
        return APITokensResponse(**data)


class APITokensResponse(Base, FromDictMixin):
    SCHEMA = APITokensResponseSchema()

    def __init__(
        self,
        id: UUID,
        name: str,
        workspace_id: int,
        type: TokenType,
        status: TokenStatus,
        created_at: datetime,
        last_used_at: Optional[datetime] = None,
        expire_at: Optional[datetime] = None,
        revoked_at: Optional[datetime] = None,
        member_id: Optional[int] = None,
        creator_id: Optional[int] = None,
        scopes: Optional[List[TokenScope]] = None,
    ):
        self.id = id
        self.name = name
        self.workspace_id = workspace_id
        self.type = type
        self.status = status
        self.created_at = created_at
        self.last_used_at = last_used_at
        self.expire_at = expire_at
        self.revoked_at = revoked_at
        self.member_id = member_id
        self.creator_id = creator_id
        self.scopes = scopes or []


@dataclass
class SecretScanPreferences:
    maximum_document_size: int = DOCUMENT_SIZE_THRESHOLD_BYTES
    maximum_documents_per_scan: int = MULTI_DOCUMENT_LIMIT


@dataclass
class RemediationMessages:
    pre_commit: str = DEFAULT_PRE_COMMIT_MESSAGE
    pre_push: str = DEFAULT_PRE_PUSH_MESSAGE
    pre_receive: str = DEFAULT_PRE_RECEIVE_MESSAGE


@dataclass
class ServerMetadata(Base, FromDictMixin):
    version: str
    preferences: Dict[str, Any]
    secret_scan_preferences: SecretScanPreferences = field(
        default_factory=SecretScanPreferences
    )
    remediation_messages: RemediationMessages = field(
        default_factory=RemediationMessages
    )


ServerMetadata.SCHEMA = cast(
    BaseSchema,
    marshmallow_dataclass.class_schema(ServerMetadata, base_schema=BaseSchema)(),
)


class JWTResponseSchema(BaseSchema):
    token = fields.String(required=True)

    @post_load
    def make_response(self, data: Dict[str, str], **kwargs: Any) -> "JWTResponse":
        return JWTResponse(**data)


class JWTResponse(Base, FromDictMixin):
    """Token to use the HasMySecretLeaked service.

    Attributes:
        token (str): the JWT token
    """

    SCHEMA = JWTResponseSchema()

    def __init__(self, token: str, **kwargs: Any) -> None:
        super().__init__()
        self.token = token

    def __repr__(self) -> str:
        return self.token


class JWTService(Enum):
    """Enum for the different services GIM can generate a JWT for."""

    HMSL = "hmsl"


@dataclass
class Detector(Base, FromDictMixin):
    name: str
    display_name: str
    nature: str
    family: str
    detector_group_name: str
    detector_group_display_name: str


Severity = Literal["info", "low", "medium", "high", "critical", "unknown"]
ValidityStatus = Literal["valid", "invalid", "failed_to_check", "no_checker", "unknown"]
IncidentStatus = Literal["IGNORED", "TRIGGERED", "RESOLVED", "ASSIGNED"]
Tag = Literal[
    "DEFAULT_BRANCH",
    "FROM_HISTORICAL_SCAN",
    "CHECK_RUN_SKIP_FALSE_POSITIVE",
    "CHECK_RUN_SKIP_LOW_RISK",
    "CHECK_RUN_SKIP_TEST_CRED",
    "IGNORED_IN_CHECK_RUN",
    "FALSE_POSITIVE",
    "PUBLICLY_EXPOSED",
    "PUBLICLY_LEAKED",
    "REGRESSION",
    "SENSITIVE_FILE",
    "TEST_FILE",
]
IgnoreReason = Literal["test_credential", "false_positive", "low_risk"]
OccurrenceKind = Literal["realtime", "historical"]
OccurrencePresence = Literal["present", "removed"]
Visibility = Literal["private", "internal", "public"]


@dataclass
class SecretPresence(Base, FromDictMixin):
    files_requiring_code_fix: int
    files_pending_merge: int
    files_fixed: int
    outside_vcs: int
    removed_outside_vcs: int
    in_vcs: int
    removed_in_vcs: int


@dataclass
class Answer(Base, FromDictMixin):
    type: str
    field_ref: str
    field_label: str
    boolean: Optional[bool] = None
    text: Optional[str] = None


@dataclass
class Feedback(Base, FromDictMixin):
    created_at: datetime
    updated_at: datetime
    member_id: int
    email: str
    answers: List[Answer]


@dataclass
class SecretIncidentStats(Base, FromDictMixin):
    total: int
    severity_breakdown: Dict[Severity, int]


@dataclass
class SecretIncidentsBreakdown(Base, FromDictMixin):
    open_secret_incidents: SecretIncidentStats
    closed_secret_incidents: SecretIncidentStats


ScanStatus = Literal[
    "pending",
    "running",
    "canceled",
    "failed",
    "too_large",
    "timeout",
    "pending_timeout",
    "finished",
]


@dataclass
class Scan(Base, FromDictMixin):
    date: datetime
    status: ScanStatus
    failing_reason: str
    commits_scanned: int
    branches_scanned: int
    duration: str


SourceHealth = Literal["safe", "unknown", "at_risk"]
SourceCriticality = Literal["critical", "high", "medium", "low", "unknown"]


@dataclass
class Source(FromDictWithBase):
    id: int
    url: str
    type: str
    full_name: str
    health: SourceHealth
    default_branch: Optional[str]
    default_branch_head: Optional[str]
    open_incidents_count: int
    closed_incidents_count: int
    secret_incidents_breakdown: SecretIncidentsBreakdown
    visibility: Visibility
    external_id: str
    source_criticality: SourceCriticality
    last_scan: Optional[Scan]
    monitored: bool


SourceSchema = cast(
    Type[BaseSchema],
    marshmallow_dataclass.class_schema(Source, base_schema=BaseSchema),
)
Source.SCHEMA = SourceSchema()


@dataclass
class OccurrenceMatch(Base, FromDictMixin):
    """
    Describes the match of an occurrence, different from the Match return as part of a PolicyBreak.

    name: type of the match such as "api_key", "password", "client_id", "client_secret"...
    indice_start: start index of the match in the document (0-based)
    indice_end: end index of the match in the document (0-based, strictly greater than indice_start)
    pre_line_start: Optional start line number (1-based) of the match in the document (before the git patch)
    pre_line_end: Optional end line number (1-based) of the match in the document (before the git patch)
    post_line_start: Optional start line number (1-based) of the match in the document (after the git patch)
    post_line_end: Optional end line number (1-based) of the match in the document (after the git patch)
    """

    name: str
    indice_start: int
    indice_end: int
    pre_line_start: Optional[int]
    pre_line_end: Optional[int]
    post_line_start: Optional[int]
    post_line_end: Optional[int]


@dataclass
class SecretOccurrence(Base, FromDictMixin):
    id: int
    incident_id: int
    kind: OccurrenceKind
    source: Source
    author_name: str
    author_info: str
    date: datetime  # Publish date
    url: str
    matches: List[OccurrenceMatch]
    tags: List[str]
    sha: Optional[str]  # Commit sha
    presence: OccurrencePresence
    filepath: Optional[str]


SecretOccurrenceSchema = cast(
    Type[BaseSchema],
    marshmallow_dataclass.class_schema(SecretOccurrence, base_schema=BaseSchema),
)
SecretOccurrence.SCHEMA = SecretOccurrenceSchema()


@dataclass(repr=False)  # the default repr would be too long
class SecretIncident(Base, FromDictMixin):
    """
    Secret Incident describes a leaked secret incident.
    """

    id: int
    date: datetime
    detector: Detector
    secret_hash: str
    hmsl_hash: str
    gitguardian_url: str
    regression: bool
    status: IncidentStatus
    assignee_id: Optional[int]
    assignee_email: Optional[str]
    occurrences_count: int
    secret_presence: SecretPresence
    ignore_reason: Optional[IgnoreReason]
    triggered_at: Optional[datetime]
    ignored_at: Optional[datetime]
    ignorer_id: Optional[int]
    ignorer_api_token_id: Optional[UUID]
    resolver_id: Optional[int]
    resolver_api_token_id: Optional[UUID]
    secret_revoked: bool
    severity: Severity
    validity: ValidityStatus
    resolved_at: Optional[datetime]
    share_url: Optional[str]
    tags: List[Tag]
    feedback_list: List[Feedback]
    occurrences: Optional[List[SecretOccurrence]]

    def __repr__(self) -> str:
        return (
            f"id:{self.id}, detector_name:{self.detector.name},"
            f"  url:{self.gitguardian_url}"
        )


SecretIncidentSchema = cast(
    Type[BaseSchema],
    marshmallow_dataclass.class_schema(SecretIncident, base_schema=BaseSchema),
)
SecretIncident.SCHEMA = SecretIncidentSchema()


class AccessLevel(str, Enum):
    OWNER = "owner"
    MANAGER = "manager"
    MEMBER = "member"
    RESTRICTED = "restricted"


@dataclass
class MembersParameters(PaginationParameter, SearchParameter, ToDictMixin):
    """
    Members query parameters
    """

    access_level: Optional[AccessLevel] = None
    active: Optional[bool] = None
    ordering: Optional[
        Literal["id", "-id", "created_at", "-created_at", "last_login", "-last_login"]
    ] = None


class MembersParametersSchema(BaseSchema):
    access_level = fields.Enum(AccessLevel, by_value=True, allow_none=True)
    active = fields.Bool(allow_none=True)
    ordering = fields.Str(allow_none=True)

    @post_load
    def make_members_parameters(self, data: Dict[str, Any], **kwargs: Any):
        return MembersParameters(**data)


MembersParameters.SCHEMA = MembersParametersSchema()


@dataclass
class Member(FromDictWithBase):
    """
    Member represents a user in a GitGuardian account.
    """

    id: int
    access_level: AccessLevel
    email: str
    name: str
    created_at: datetime
    last_login: Optional[datetime]
    active: bool


class MemberSchema(BaseSchema):
    """
    This schema cannot be done through marshmallow_dataclass as we want to use the
    values of the AccessLevel enum to create the enum field
    """

    id = fields.Int(required=True)
    access_level = fields.Enum(AccessLevel, by_value=True, required=True)
    email = fields.Str(required=True)
    name = fields.Str(required=True)
    created_at = fields.AwareDateTime(required=True)
    last_login = fields.AwareDateTime(allow_none=True)
    active = fields.Bool(required=True)

    @post_load
    def return_member(
        self,
        data: Dict[str, Any],
        **kwargs: Any,
    ):
        return Member(**data)


Member.SCHEMA = MemberSchema()


class UpdateMemberSchema(BaseSchema):
    """
    This schema cannot be done through marshmallow_dataclass as we want to use the
    values of the AccessLevel enum to create the enum field
    """

    id = fields.Int(required=True)
    access_level = fields.Enum(AccessLevel, by_value=True, allow_none=True)
    active = fields.Bool(allow_none=True)

    @post_dump
    def access_level_value(self, data: Dict[str, Any], **kwargs: Any) -> Dict[str, Any]:
        if "access_level" in data:
            data["access_level"] = AccessLevel(data["access_level"]).value
        return data


@dataclass
class UpdateMember(FromDictWithBase):
    """
    UpdateMember represents the payload to update a member
    """

    id: int
    access_level: Optional[AccessLevel] = None
    active: Optional[bool] = None


UpdateMember.SCHEMA = UpdateMemberSchema()


@dataclass
class UpdateMemberParameters(FromDictWithBase):
    send_email: Optional[bool] = None


UpdateMemberParametersSchema = cast(
    Type[BaseSchema],
    marshmallow_dataclass.class_schema(UpdateMemberParameters, base_schema=BaseSchema),
)
UpdateMemberParameters.SCHEMA = UpdateMemberParametersSchema()


@dataclass
class DeleteMemberParameters(FromDictWithBase):
    id: int
    send_email: Optional[bool] = None


DeleteMemberParametersSchema = cast(
    Type[BaseSchema],
    marshmallow_dataclass.class_schema(DeleteMemberParameters, base_schema=BaseSchema),
)
DeleteMemberParameters.SCHEMA = DeleteMemberParametersSchema()


@dataclass
class TeamsParameters(PaginationParameter, SearchParameter, FromDictMixin, ToDictMixin):
    is_global: Optional[bool] = None


TeamsParameterSchema = cast(
    Type[BaseSchema],
    marshmallow_dataclass.class_schema(TeamsParameters, base_schema=BaseSchema),
)
TeamsParameters.SCHEMA = TeamsParameterSchema()


@dataclass
class Team(FromDictWithBase):
    id: int
    name: str
    is_global: bool
    gitguardian_url: str
    description: Optional[str] = None


TeamsSchema = cast(
    Type[BaseSchema],
    marshmallow_dataclass.class_schema(Team, base_schema=BaseSchema),
)
Team.SCHEMA = TeamsSchema()


@dataclass
class CreateTeam(FromDictWithBase):
    name: str
    description: Optional[str] = ""


CreateTeamSchema = cast(
    Type[BaseSchema],
    marshmallow_dataclass.class_schema(CreateTeam, base_schema=BaseSchema),
)


CreateTeam.SCHEMA = CreateTeamSchema()


@dataclass
class UpdateTeam(FromDictWithBase):
    id: int
    name: Optional[str]
    description: Optional[str] = None


UpdateTeamSchema = cast(
    Type[BaseSchema],
    marshmallow_dataclass.class_schema(UpdateTeam, base_schema=BaseSchema),
)
UpdateTeam.SCHEMA = UpdateTeamSchema()


class TeamPermission(str, Enum):
    MANAGER = "can_manage"
    MEMBER = "cannot_manage"


class IncidentPermission(str, Enum):
    EDIT = "can_edit"
    VIEW = "can_view"
    FULL_ACCESS = "full_access"


@dataclass
class TeamInvitationParameters(PaginationParameter, ToDictMixin):
    invitation_id: Optional[int] = None
    is_team_leader: Optional[bool] = None
    incident_permission: Optional[IncidentPermission] = None


class TeamInvitationParameterSchema(BaseSchema):
    invitation_id = fields.Int(allow_none=True)
    is_team_leader = fields.Bool(allow_none=True)
    incident_permission = fields.Enum(
        IncidentPermission, by_value=True, allow_none=True
    )

    class Meta:
        exclude_none = True


TeamInvitationParameters.SCHEMA = TeamInvitationParameterSchema()


@dataclass
class TeamInvitation(FromDictWithBase):
    id: int
    invitation_id: int
    team_id: int
    team_permission: TeamPermission
    incident_permission: IncidentPermission


class TeamInvitationSchema(BaseSchema):
    many = False

    id = fields.Int(required=True)
    invitation_id = fields.Int(required=True)
    team_id = fields.Int(required=True)
    team_permission = fields.Enum(TeamPermission, by_value=True, required=True)
    incident_permission = fields.Enum(IncidentPermission, by_value=True, required=True)

    @post_load
    def make_team_invitation(
        self,
        data: Dict[str, Any],
        **kwargs: Any,
    ):
        return TeamInvitation(**data)


TeamInvitation.SCHEMA = TeamInvitationSchema()


@dataclass
class CreateTeamInvitation(FromDictWithBase):
    invitation_id: int
    is_team_leader: bool
    incident_permission: IncidentPermission


class CreateTeamInvitationSchema(BaseSchema):
    many = False

    invitation_id = fields.Int(required=True)
    is_team_leader = fields.Bool(required=True)
    incident_permission = fields.Enum(IncidentPermission, by_value=True, required=True)

    @post_load
    def make_team_invitation(self, data: Dict[str, Any], **kwargs: Any):
        return CreateTeamInvitation(**data)

    class Meta:
        exclude_none = True


CreateTeamInvitation.SCHEMA = CreateTeamInvitationSchema()


@dataclass
class TeamMemberParameters(PaginationParameter, SearchParameter, ToDictMixin):
    is_team_leader: Optional[bool] = None
    incident_permission: Optional[IncidentPermission] = None
    member_id: Optional[int] = None


class TeamMembershipParameterSchema(BaseSchema):
    is_team_leader = fields.Bool(allow_none=True)
    incident_permission = fields.Enum(
        IncidentPermission, by_value=True, allow_none=True
    )
    member_id = fields.Int(allow_none=True)

    @post_load
    def make_team_member_parameter(self, data: Dict[str, Any], **kwargs: Any):
        return TeamMemberParameters(**data)

    class Meta:
        exclude_none = True


TeamMemberParameters.SCHEMA = TeamMembershipParameterSchema()


@dataclass
class TeamMember(FromDictWithBase):
    id: int
    team_id: int
    member_id: int
    is_team_leader: bool
    team_permission: TeamPermission
    incident_permission: IncidentPermission


class TeamMemberSchema(BaseSchema):
    id = fields.Int(required=True)
    team_id = fields.Int(required=True)
    member_id = fields.Int(required=True)
    is_team_leader = fields.Bool(required=True)
    team_permission = fields.Enum(TeamPermission, by_value=True, required=True)
    incident_permission = fields.Enum(IncidentPermission, by_value=True, required=True)

    @post_load
    def make_team_member(self, data: Dict[str, Any], **kwargs: Any):
        return TeamMember(**data)


TeamMember.SCHEMA = TeamMemberSchema()


@dataclass
class CreateTeamMemberParameters(ToDictMixin):
    send_email: Optional[bool] = None


CreateTeamMemberParameterSchema = cast(
    Type[BaseSchema],
    marshmallow_dataclass.class_schema(
        CreateTeamMemberParameters, base_schema=BaseSchema
    ),
)
CreateTeamMemberParameters.SCHEMA = CreateTeamMemberParameterSchema()


@dataclass
class CreateTeamMember(FromDictWithBase):
    member_id: int
    is_team_leader: bool
    incident_permission: IncidentPermission


class CreateTeamMemberSchema(BaseSchema):
    many = False

    member_id = fields.Int(required=True)
    is_team_leader = fields.Bool(required=True)
    incident_permission = fields.Enum(IncidentPermission, by_value=True, required=True)

    @post_load
    def make_create_team_member(self, data: Dict[str, Any], **kwargs: Any):
        return CreateTeamMember(**data)


CreateTeamMember.SCHEMA = CreateTeamMemberSchema()


@dataclass
class TeamSourceParameters(PaginationParameter, SearchParameter, ToDictMixin):
    last_scan_status: Optional[ScanStatus] = None
    type: Optional[str] = None
    health: Optional[SourceHealth] = None
    type: Optional[str] = None
    ordering: Optional[Literal["last_scan_date", "-last_scan_date"]] = None
    visibility: Optional[Visibility] = None
    external_id: Optional[str] = None


TeamSourceParametersSchema = cast(
    Type[BaseSchema],
    marshmallow_dataclass.class_schema(TeamSourceParameters, base_schema=BaseSchema),
)
TeamSourceParameters.SCHEMA = TeamSourceParametersSchema()


@dataclass
class UpdateTeamSource(FromDictWithBase):
    team_id: int
    sources_to_add: List[int]
    sources_to_remove: List[int]


UpdateTeamSourceSchema = cast(
    Type[BaseSchema],
    marshmallow_dataclass.class_schema(UpdateTeamSource, base_schema=BaseSchema),
)
UpdateTeamSource.SCHEMA = UpdateTeamSourceSchema()


@dataclass
class SourceParameters(TeamSourceParameters):
    source_criticality: Optional[SourceCriticality] = None
    monitored: Optional[bool] = None


SourceParametersSchema = cast(
    Type[BaseSchema],
    marshmallow_dataclass.class_schema(SourceParameters, base_schema=BaseSchema),
)
SourceParameters.SCHEMA = SourceParametersSchema()


@dataclass
class InvitationParameters(
    PaginationParameter, SearchParameter, FromDictMixin, ToDictMixin
):
    ordering: Optional[Literal["date", "-date"]] = None


@dataclass
class Invitation(FromDictWithBase):
    id: int
    email: str
    access_level: AccessLevel
    date: datetime


class InvitationSchema(BaseSchema):
    id = fields.Int(required=True)
    email = fields.Str(required=True)
    access_level = fields.Enum(AccessLevel, by_value=True, required=True)
    date = fields.DateTime(required=True)

    @post_load
    def make_invitation(self, data: Dict[str, Any], **kwargs: Any):
        return Invitation(**data)


Invitation.SCHEMA = InvitationSchema()


@dataclass
class CreateInvitationParameters(FromDictMixin, ToDictMixin):
    send_email: Optional[bool] = None


CreateInvitationParameterSchema = cast(
    Type[BaseSchema],
    marshmallow_dataclass.class_schema(
        CreateInvitationParameters, base_schema=BaseSchema
    ),
)
CreateInvitationParameters.SCHEMA = CreateInvitationParameterSchema()


@dataclass
class CreateInvitation(FromDictMixin, ToDictMixin):
    email: str
    access_level: AccessLevel


class CreateInvitationSchema(BaseSchema):
    email = fields.Str(required=True)
    access_level = fields.Enum(AccessLevel, by_value=True, required=True)

    @post_load
    def make_create_invitation(self, data: Dict[str, Any], **kwargs: Any):
        return CreateInvitation(**data)


CreateInvitation.SCHEMA = CreateInvitationSchema()
