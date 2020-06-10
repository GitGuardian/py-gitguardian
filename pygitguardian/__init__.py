"""PyGitGuardian API Client"""
from .client import GGClient


__version__ = "1.0.4"
GGClient._version = __version__

__all__ = [
    "GGClient",
]
