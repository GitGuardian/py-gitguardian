from dataclasses import dataclass, field
from typing import List, Optional

import marshmallow_dataclass

from pygitguardian.models import Base, BaseSchema


@dataclass
class IaCVulnerability(Base):
    policy: str
    policy_id: str
    line_end: int
    line_start: int
    description: str
    documentation_url: str
    component: str = ""
    severity: str = ""


IaCVulnerabilitySchema = marshmallow_dataclass.class_schema(
    IaCVulnerability, BaseSchema
)


@dataclass
class IaCFileResult(Base):
    filename: str
    incidents: List[IaCVulnerability]


IaCFileResultSchema = marshmallow_dataclass.class_schema(IaCFileResult, BaseSchema)


@dataclass
class IaCScanParameters(Base):
    ignored_policies: List[str] = field(default_factory=list)
    minimum_severity: Optional[str] = None


IaCScanParametersSchema = marshmallow_dataclass.class_schema(
    IaCScanParameters, BaseSchema
)


@dataclass
class IaCScanResult(Base):
    id: str = ""
    type: str = ""
    iac_engine_version: str = ""
    entities_with_incidents: List[IaCFileResult] = field(default_factory=list)


IaCScanResultSchema = marshmallow_dataclass.class_schema(IaCScanResult, BaseSchema)
