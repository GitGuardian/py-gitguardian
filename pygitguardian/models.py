from typing import Dict, List, Optional

from marshmallow import (
    EXCLUDE,
    Schema,
    ValidationError,
    fields,
    post_load,
    validate,
    validates,
)

from .config import DOCUMENT_SIZE_THRESHOLD_BYTES


class Base:
    SCHEMA = None

    def __init__(self):
        self.status_code = None

    def to_json(self) -> str:
        """
        to_json converts model to JSON string.
        """
        return self.SCHEMA.dumps(self)

    def to_dict(self) -> Dict:
        """
        to_dict converts model to a dictionary representation.
        """
        return self.SCHEMA.dump(self)

    @property
    def success(self) -> bool:
        return self.__bool__()

    def __bool__(self) -> bool:
        return self.status_code == 200


class DocumentSchema(Schema):
    class Meta:
        unknown = EXCLUDE

    filename = fields.String(validate=validate.Length(max=256), allow_none=True)
    document = fields.String(required=True)

    @validates("document")
    def validate_document(self, document: str) -> str:
        """
        validate that document is smaller than scan limit
        """
        encoded = document.encode("utf-8")
        if len(encoded) > DOCUMENT_SIZE_THRESHOLD_BYTES:
            raise ValidationError(
                "file exceeds the maximum allowed size of {}B".format(
                    DOCUMENT_SIZE_THRESHOLD_BYTES
                )
            )

        if "\x00" in document:
            raise ValidationError("document has null characters")

        return document


class Document(Base):
    """
    Document is a request object for communicating documents
    to the API

    Attributes:
        filename (optional,str): filename for filename evaluation
        document (str): text content
    """

    SCHEMA = DocumentSchema()

    def __init__(self, document: str, filename: Optional[str] = None, **kwargs):
        super().__init__()
        self.document = document
        if filename:
            self.filename = filename

    def __repr__(self):
        return "filename:{0}, document:{1}".format(self.filename, self.document)


class DetailSchema(Schema):
    detail = fields.String(required=True)

    @post_load
    def make_detail_response(self, data, **kwargs):
        return Detail(**data)


class Detail(Base):
    """Detail is a response object mostly returned on error or when the
    api output is a simple string.

    Attributes:
        status_code (int): response status code
        detail (str): response string
    """

    SCHEMA = DetailSchema()

    def __init__(self, detail: str, **kwargs):
        super().__init__()
        self.detail = detail

    def __repr__(self):
        return "{0}:{1}".format(self.status_code, self.detail)


class MatchSchema(Schema):
    match = fields.String(required=True)
    match_type = fields.String(data_key="type", required=True)
    line_start = fields.Int(allow_none=True)
    line_end = fields.Int(allow_none=True)
    index_start = fields.Int(allow_none=True)
    index_end = fields.Int(allow_none=True)

    @post_load
    def make_match(self, data, **kwargs):
        return Match(**data)


class Match(Base):
    """
    Match describes a found issue by GitGuardian.
    With info such as match location and type.
    Example:
    { "match": "cake.gitguardian.com",
    "index_end": 96,
    "index_start": 77,
    "type": "host",
    "line_end": 2,
    "line_start": 2 }
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
        **kwargs
    ):
        self.match = match
        self.match_type = match_type
        self.line_start = line_start
        self.line_end = line_end
        self.index_start = index_start
        self.index_end = index_end

    def __repr__(self):
        return (
            "match:{0}, "
            "match_type:{1}, "
            "line_start:{2}, "
            "line_end:{3}, "
            "index_start:{4}, "
            "index_end:{5}".format(
                self.match,
                self.match_type,
                repr(self.line_start),
                repr(self.line_end),
                repr(self.index_start),
                repr(self.index_end),
            )
        )


class PolicyBreakSchema(Schema):
    break_type = fields.String(data_key="type", required=True)
    policy = fields.String(required=True)
    matches = fields.List(fields.Nested(MatchSchema), required=True)

    @post_load
    def make_policy_break(self, data, **kwargs):
        return PolicyBreak(**data)


class PolicyBreak(Base):
    """
    PolicyBreak describes a GitGuardian policy break found
    in a scan.
    A PolicyBreak can contain multiple matches, for example,
    on secrets that have a client id and client secret.
    """

    SCHEMA = PolicyBreakSchema()

    def __init__(self, break_type: str, policy: str, matches: List[Match], **kwargs):
        self.break_type = break_type
        self.policy = policy
        self.matches = matches

    def __repr__(self):
        return (
            "break_type:{0}, "
            "policy:{1}, "
            "matches: {2}".format(self.break_type, self.policy, repr(self.matches))
        )


class ScanResultSchema(Schema):
    policy_break_count = fields.Integer(required=True)
    policies = fields.List(fields.String(), required=True)
    policy_breaks = fields.List(fields.Nested(PolicyBreakSchema), required=True)

    @post_load
    def make_scan_result(self, data, **kwargs):
        return ScanResult(**data)


class ScanResult(Base):
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
        **kwargs
    ):
        """
        :param policy_break_count: number of policy breaks
        :type policy_break_count: int
        :param policy_breaks: policy break list
        :type policy_breaks: List
        :param policies: string list of policies evaluated
        :type policies: List[str]
        """
        super().__init__()
        self.policy_break_count = policy_break_count
        self.policies = policies
        self.policy_breaks = policy_breaks

    @property
    def has_secrets(self) -> bool:
        """has_secrets is an easy way to check if your provided document has policy breaks

        >>> obj = ScanResult(2, [], [])
        >>> obj.has_secrets
        True

        :return: true if there were policy breaks in the documents
        :rtype: bool
        """

        return self.policy_break_count > 0

    def __repr__(self):
        return (
            "policy_break_count:{0}, "
            "policies:{1}, "
            "policy_breaks: {2}".format(
                self.policy_break_count, self.policies, self.policy_breaks
            )
        )

    def __str__(self):
        return "{0} policy breaks from the evaluated policies: {1}".format(
            self.policy_break_count,
            ", ".join([policy_break.policy for policy_break in self.policy_breaks]),
        )


class MultiScanResultSchema(Schema):
    scan_results = fields.List(
        fields.Nested(ScanResultSchema),
        required=True,
        validates=validate.Length(min=1),
    )

    @post_load
    def make_scan_result(self, data, **kwargs):
        return MultiScanResult(**data)


class MultiScanResult(Base):
    """ScanResult is a response object returned on a Content Scan

    Attributes:
        status_code (int): response status code
        policy_break_count (int): number of policy breaks
        policy_breaks (List): policy break list
        policies (List[str]): string list of policies evaluated
    """

    SCHEMA = MultiScanResultSchema()

    def __init__(self, scan_results: List[ScanResult], **kwargs):
        """
        :param scan_results: List of scan_results
        """
        super().__init__()
        self.scan_results = scan_results

    @property
    def has_secrets(self) -> bool:
        """has_secrets is an easy way to check if your provided document has policy breaks

        >>> obj = ScanResult(2, [], [])
        >>> obj.has_secrets
        True

        :return: true if there were policy breaks in the documents
        :rtype: bool
        """

        return any(
            (len(scan_result.policy_breaks) > 0 for scan_result in self.scan_results)
        )

    def __repr__(self):
        return "scan_results:{0}".format(self.scan_results)

    def __str__(self):
        return "{0} scan results containing {1} policy breaks".format(
            len(self.scan_results),
            len(
                [
                    policy_break
                    for scan_result in self.scan_results
                    for policy_break in scan_result.policy_breaks
                ]
            ),
        )
