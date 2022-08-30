import os


DEFAULT_BASE_URI = "https://api.gitguardian.com"
DEFAULT_API_VERSION = "v1"
DEFAULT_TIMEOUT = 20.0  # 20s default timeout

MULTI_DOCUMENT_LIMIT = 20

try:
    DOCUMENT_SIZE_THRESHOLD_BYTES = int(os.environ["GG_MAX_FILE_SIZE"])
except KeyError:
    DOCUMENT_SIZE_THRESHOLD_BYTES = 10 * 1024 * 1024
