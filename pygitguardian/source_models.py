from dataclasses import dataclass, field
from datetime import datetime
from enum import auto

from marshmallow_dataclass import class_schema
from strenum import SnakeCaseStrEnum

from pygitguardian.models import Base, BaseSchema


class ScanStatus(SnakeCaseStrEnum):
    PENDING = auto()
    RUNNING = auto()
    CANCELED = auto()
    FAILED = auto()
    TOO_LARGE = auto()
    TIMEOUT = auto()
    FINISHED = auto()


@dataclass
class Scan(Base):
    date: datetime
    status: ScanStatus = field(metadata={"by_value": True})


ScanSchema = class_schema(Scan, BaseSchema)


class SourceHealth(SnakeCaseStrEnum):
    SAFE = auto()
    UNKNOWN = auto()
    AT_RISK = auto()


@dataclass
class Source(Base):
    id: int
    url: str
    type: str  # TODO: Reserved word
    full_name: str
    health: SourceHealth = field(metadata={"by_value": True})
    open_incidents_count: int  # TODO: Type documented as "number" - what's the difference?
    closed_incidents_count: int  # TODO: Also "number"
    visibility: str  # TODO: Really? str
    external_id: str
    last_scan: Scan


SourceSchema = class_schema(Source, BaseSchema)
