"""PyGitGuardian API Client"""
from .client import GGClient


__version__ = "1.2.3"
GGClient._version = __version__

__all__ = [
    "GGClient",
]
