from enum import auto

from strenum import LowercaseStrEnum, MacroCaseStrEnum, SnakeCaseStrEnum, StrEnum


class IncidentIgnoreReason(SnakeCaseStrEnum):
    TEST_CREDENTIAL = auto()
    FALSE_POSITIVE = auto()
    LOW_RISK = auto()


class IncidentOrdering(StrEnum):
    DATE_ASC = "date"
    DATE_DESC = "-date"
    RESOLVED_AT_ASC = "resolved_at"
    RESOLVED_AT_DESC = "-resolved_at"
    IGNORED_AT_ASC = "ignored_at"
    IGNORED_AT_DESC = "-ignored_at"


class IncidentPermission(LowercaseStrEnum):
    CAN_VIEW = auto()
    CAN_EDIT = auto()
    FULL_ACCESS = auto()


class IncidentSeverity(SnakeCaseStrEnum):
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFO = auto()
    UNKNOWN = auto()


class IncidentStatus(MacroCaseStrEnum):
    IGNORED = auto()
    TRIGGERED = auto()
    ASSIGNED = auto()
    RESOLVED = auto()


class IncidentTag(MacroCaseStrEnum):
    DEFAULT_BRANCH = auto()
    FROM_HISTORICAL_SCAN = auto()
    IGNORED_IN_CHECK_RUN = auto()
    PUBLIC = auto()
    PUBLICLY_EXPOSED = auto()
    PUBLICLY_LEAKED = auto()
    REGRESSION = auto()
    SENSITIVE_FILE = auto()
    TEST_FILE = auto()


class IncidentValidity(SnakeCaseStrEnum):
    VALID = auto()
    INVALID = auto()
    FAILED_TO_CHECK = auto()
    NO_CHECKER = auto()
    UNKNOWN = auto()


class OccurrenceKind(LowercaseStrEnum):
    REALTIME = auto()
    HISTORICAL = auto()


class OccurrencePresence(SnakeCaseStrEnum):
    present = auto()
    removed = auto()
