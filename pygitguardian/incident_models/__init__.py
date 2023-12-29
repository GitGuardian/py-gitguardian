from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Type, Union, cast

from marshmallow_dataclass import class_schema

from pygitguardian.incident_models.constants import (
    IncidentIgnoreReason,
    IncidentSeverity,
    IncidentStatus,
    IncidentTag,
    IncidentValidity,
    OccurrenceKind,
    OccurrencePresence,
)
from pygitguardian.models import Base, BaseSchema, FromDictMixin
from pygitguardian.source_models import Source


@dataclass
class Detector(Base, FromDictMixin):
    name: str
    display_name: str
    nature: str
    family: str
    detector_group_name: str
    detector_group_display_name: str


DetectorSchema = cast(Type[BaseSchema], class_schema(Detector, BaseSchema))
Detector.SCHEMA = DetectorSchema()


@dataclass
class Match(Base, FromDictMixin):
    name: str
    indice_start: int
    indice_end: int
    pre_line_start: Optional[int]
    pre_line_end: Optional[int]
    post_line_start: Optional[int]
    post_line_end: Optional[int]


MatchSchema = cast(Type[BaseSchema], class_schema(Match, BaseSchema))
Match.SCHEMA = MatchSchema()


@dataclass
class Occurrence(Base, FromDictMixin):
    id: int
    incident_id: int
    kind: OccurrenceKind = field(metadata={"by_value": True})
    sha: str
    source: Source
    author_name: str
    author_info: str
    date: datetime
    presence: OccurrencePresence = field(metadata={"by_value": True})
    url: str
    matches: List[Match]
    filepath: str


OccurrenceSchema = cast(Type[BaseSchema], class_schema(Occurrence, BaseSchema))
Occurrence.SCHEMA = OccurrenceSchema()


@dataclass
class Incident(Base, FromDictMixin):
    id: int
    date: datetime
    detector: Detector
    secret_hash: str
    gitguardian_url: str
    regression: bool
    status: IncidentStatus = field(metadata={"by_value": True})
    assignee_email: Optional[str]
    occurrences_count: int
    occurrences: Optional[List[Occurrence]]
    ignore_reason: Optional[IncidentIgnoreReason] = field(metadata={"by_value": True})
    ignored_at: Optional[datetime]
    secret_revoked: bool
    severity: IncidentSeverity = field(metadata={"by_value": True})
    validity: IncidentValidity = field(metadata={"by_value": True})
    resolved_at: Optional[datetime]
    share_url: Optional[str]
    tags: List[IncidentTag] = field(metadata={"by_value": True})

    def __int__(self):
        return self.id


IncidentSchema = cast(Type[BaseSchema], class_schema(Incident, BaseSchema))
Incident.SCHEMA = IncidentSchema()


@dataclass
class Link:
    url: str
    rel: str


@dataclass
class Links:
    next: Optional[Link]
    prev: Optional[Link]


@dataclass
class ListIncidentResult(Base, FromDictMixin):
    incidents: List[Incident]
    links: Optional[Links] = None


ListIncidentResultSchema = cast(
    Type[BaseSchema], class_schema(ListIncidentResult, BaseSchema)
)
ListIncidentResult.SCHEMA = ListIncidentResultSchema()


@dataclass
class SharedIncidentDetails(Base, FromDictMixin):
    incident_id: int
    share_url: str
    feedback_collection: bool
    auto_healing: bool
    token: str
    expire_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None


SharedIncidentDetailsSchema = cast(
    Type[BaseSchema], class_schema(SharedIncidentDetails, BaseSchema)
)
SharedIncidentDetails.SCHEMA = SharedIncidentDetailsSchema()

IncidentIdOrIncident = Union[int, Incident]
