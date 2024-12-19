# pyright: reportIncompatibleVariableOverride=false
# Disable this check because of multiple non-dangerous violations (SCHEMA variables,
# BaseSchema.Meta class)
from dataclasses import dataclass
from typing import (
    TYPE_CHECKING,
    Any,
    ClassVar,
    Dict,
    Generic,
    List,
    Optional,
    Type,
    TypeVar,
    cast,
)

from marshmallow import EXCLUDE, Schema
from typing_extensions import Self


if TYPE_CHECKING:
    import requests


class ToDictMixin:
    """
    Provides a type-safe `to_dict()` method for classes using Marshmallow
    """

    SCHEMA: ClassVar[Schema]

    def to_dict(self) -> Dict[str, Any]:
        return cast(Dict[str, Any], self.SCHEMA.dump(self))


class FromDictMixin:
    """This class must be used as an additional base class for all classes whose schema
    implements a `post_load` function turning the received dict into a class instance.

    It makes it possible to deserialize an object using `MyClass.from_dict(dct)` instead
    of `MyClass.SCHEMA.load(dct)`. The `from_dict()` method is shorter, but more
    importantly, type-safe: its return type is an instance of `MyClass`, not
    `list[Any] | Any`.

    Reference: https://marshmallow.readthedocs.io/en/stable/quickstart.html#deserializing-to-objects  E501
    """

    SCHEMA: ClassVar[Schema]

    @classmethod
    def from_dict(cls, dct: Dict[str, Any]) -> Self:
        return cast(Self, cls.SCHEMA.load(dct))


class BaseSchema(Schema):
    class Meta:
        ordered = True
        unknown = EXCLUDE


class Base(ToDictMixin):
    def __init__(self, status_code: Optional[int] = None) -> None:
        self.status_code = status_code

    def to_json(self) -> str:
        """
        to_json converts model to JSON string.
        """
        return cast(str, self.SCHEMA.dumps(self))

    @property
    def success(self) -> bool:
        return self.__bool__()

    def __bool__(self) -> bool:
        return self.status_code == 200


@dataclass
class PaginationParameter(ToDictMixin):
    """Pagination mixin used for endpoints that support pagination."""

    cursor: str = ""
    per_page: int = 20


@dataclass
class SearchParameter(ToDictMixin):
    search: Optional[str] = None


class FromDictWithBase(FromDictMixin, Base):
    pass


PaginatedData = TypeVar("PaginatedData", bound=FromDictWithBase)


@dataclass
class CursorPaginatedResponse(Generic[PaginatedData]):
    status_code: int
    data: List[PaginatedData]
    prev: Optional[str] = None
    next: Optional[str] = None

    @classmethod
    def from_response(
        cls, response: "requests.Response", data_type: Type[PaginatedData]
    ) -> "CursorPaginatedResponse[PaginatedData]":
        data = cast(
            List[PaginatedData], [data_type.from_dict(obj) for obj in response.json()]
        )
        for element in data:
            element.status_code = response.status_code

        paginated_response = cls(status_code=response.status_code, data=data)

        if previous_page := response.links.get("prev"):
            paginated_response.prev = previous_page["url"]
        if next_page := response.links.get("next"):
            paginated_response.next = next_page["url"]

        return paginated_response
