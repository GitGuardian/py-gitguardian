DEFAULT_BASE_URI = "https://api.gitguardian.com"
DEFAULT_API_VERSION = "v1"
DEFAULT_TIMEOUT = 20.0  # 20s default timeout

MULTI_DOCUMENT_LIMIT = 20
DOCUMENT_SIZE_THRESHOLD_BYTES = 1048576  # 1MB
MAXIMUM_PAYLOAD_SIZE = 2621440  # 25MB

DEFAULT_PRE_COMMIT_MESSAGE = """Since the secret was detected before the commit was made:
1. replace the secret with its reference (e.g. environment variable).
2. commit again."""

DEFAULT_PRE_PUSH_MESSAGE = """Since the secret was detected before the push BUT after the commit, you need to:
1. rewrite the git history making sure to replace the secret with its reference (e.g. environment variable).
2. push again."""

DEFAULT_PRE_RECEIVE_MESSAGE = """A pre-receive hook set server side prevented you from pushing secrets.
Since the secret was detected during the push BUT after the commit, you need to:
1. rewrite the git history making sure to replace the secret with its reference (e.g. environment variable).
2. push again."""
