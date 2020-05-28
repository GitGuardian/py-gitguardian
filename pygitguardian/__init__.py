"""PyGitGuardian API Client"""
from .client import GGClient
from .models import (
    Detail,
    DetailSchema,
    DocumentSchema,
    Match,
    PolicyBreak,
    ScanResult,
    ScanResultSchema,
)


__version__ = "1.0.3"
GGClient._version = __version__

__all__ = [
    "Detail",
    "DetailSchema",
    "DocumentSchema",
    "GGClient",
    "Match",
    "PolicyBreak",
    "ScanResult",
    "ScanResultSchema",
]
