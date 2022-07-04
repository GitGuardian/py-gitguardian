"""PyGitGuardian API Client"""
from .client import GGClient


__version__ = "1.3.5"
GGClient._version = __version__

__all__ = [
    "GGClient",
]
