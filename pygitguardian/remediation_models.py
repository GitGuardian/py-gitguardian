from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Type, Union, cast

import marshmallow_dataclass
from marshmallow import fields

from pygitguardian.models import Base, BaseSchema, FromDictMixin


class SourceHealth(Enum):
    """Enum for the different health of a source."""

    SAFE = "safe"
    UNKNOWN = "unknown"
    AT_RISK = "at_risk"


class SourceCriticality(Enum):
    """Enum for the different criticality of a source."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "unknown"


class SourceScanStatus(Enum):
    """Enum for the different status of a source scan."""

    PENDING = "pending"
    RUNNING = "running"
    CANCELED = "canceled"
    FAILED = "failed"
    TOO_LARGE = "too_large"
    TIMEOUT = "timeout"
    FINISHED = "finished"


@dataclass
class SourceScan(BaseSchema):
    """Represents a scan of a source."""

    date: str = fields.Date()
    status: str = fields.Enum(SourceScanStatus)
    failing_reason: Union[str, None] = fields.String(allow_none=True)
    commits_scanned: int = fields.Int()
    branches_scanned: int = fields.Int()
    duration: str = fields.String()


@dataclass
class Source(BaseSchema):
    """Represents a source."""

    id: int = fields.Int()
    url: str = fields.URL()
    type: str = fields.String()
    full_name: str = fields.String()
    health: str = fields.Enum(SourceHealth)
    default_branch: Union[str, None] = fields.String(allow_none=True)
    default_branch_head: Union[str, None] = fields.String(allow_none=True)
    open_incidents_count: int = fields.Int()
    closed_incidents_count: int = fields.Int()
    secret_incidents_breakdown: Dict[str, Any] = fields.Dict(keys=fields.Str())
    visibility: str = fields.String()
    external_id: str = fields.String()
    source_criticality: str = fields.Enum(SourceCriticality)
    last_scan: Dict[str, Any] = fields.Dict(keys=fields.Str())


class ListSourcesResponse(Base, FromDictMixin):
    """Represents a list of sources."""

    sources: List[Source] = fields.List(fields.Nested(Source))


ListSourcesResponseSchema = cast(
    Type[BaseSchema],
    marshmallow_dataclass.class_schema(ListSourcesResponse, base_schema=BaseSchema),
)
ListSourcesResponse.SCHEMA = ListSourcesResponseSchema()
