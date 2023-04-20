"""PyGitGuardian API Client"""
from .client import ContentTooLarge, GGClient


__version__ = "1.6.0"
GGClient._version = __version__

__all__ = ["GGClient", "ContentTooLarge"]
