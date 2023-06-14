from dataclasses import dataclass, field
from typing import List, Optional, Type, cast

import marshmallow_dataclass

from pygitguardian.models import Base, BaseSchema, FromDictMixin


@dataclass
class IaCVulnerability(Base, FromDictMixin):
    policy: str
    policy_id: str
    line_end: int
    line_start: int
    description: str
    documentation_url: str
    component: str = ""
    severity: str = ""


IaCVulnerabilitySchema = cast(
    Type[BaseSchema], marshmallow_dataclass.class_schema(IaCVulnerability, BaseSchema)
)

IaCVulnerability.SCHEMA = IaCVulnerabilitySchema()


@dataclass
class IaCFileResult(Base, FromDictMixin):
    filename: str
    incidents: List[IaCVulnerability]


IaCFileResultSchema = cast(
    Type[BaseSchema], marshmallow_dataclass.class_schema(IaCFileResult, BaseSchema)
)

IaCFileResult.SCHEMA = IaCFileResultSchema()


@dataclass
class IaCScanParameters(Base, FromDictMixin):
    ignored_policies: List[str] = field(default_factory=list)
    minimum_severity: Optional[str] = None


IaCScanParametersSchema = cast(
    Type[BaseSchema], marshmallow_dataclass.class_schema(IaCScanParameters, BaseSchema)
)

IaCScanParameters.SCHEMA = IaCScanParametersSchema()


@dataclass
class IaCScanResult(Base, FromDictMixin):
    id: str = ""
    type: str = ""
    iac_engine_version: str = ""
    entities_with_incidents: List[IaCFileResult] = field(default_factory=list)


IaCScanResultSchema = cast(
    Type[BaseSchema], marshmallow_dataclass.class_schema(IaCScanResult, BaseSchema)
)
IaCScanResult.SCHEMA = IaCScanResultSchema()
