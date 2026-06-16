"""PyGitGuardian API Client"""

import sys
import warnings

from .client import ContentTooLarge, GGClient, GGClientCallbacks


if sys.version_info < (3, 9):
    warnings.warn(
        "Python 3.8 support is deprecated and will be removed in a future "
        "py-gitguardian release; upgrade to Python 3.9+.",
        DeprecationWarning,
        stacklevel=2,
    )


__version__ = "1.31.0"
GGClient._version = __version__

__all__ = ["GGClient", "GGClientCallbacks", "ContentTooLarge"]
