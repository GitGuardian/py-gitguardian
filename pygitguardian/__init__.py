"""PyGitGuardian API Client"""
from .client import ContentTooLarge, GGClient, GGClientCallbacks


__version__ = "1.14.0"
GGClient._version = __version__

__all__ = ["GGClient", "GGClientCallbacks", "ContentTooLarge"]
