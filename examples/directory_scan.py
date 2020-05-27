import glob
import os
import sys
import traceback

from pygitguardian import GGClient
from pygitguardian.config import MULTI_DOCUMENT_LIMIT


API_KEY = os.getenv("GG_API_KEY")

client = GGClient(token=API_KEY)

# Create a list of dictionaries for scanning
to_scan = []
for name in glob.glob("**/*"):
    with open(name) as fn:
        to_scan.append({"document": fn.read(), "filename": os.path.basename(name)})

# Process in a chunked way to avoid passing the multi document limit
to_process = []
for i in range(0, len(to_scan), MULTI_DOCUMENT_LIMIT):
    chunk = to_scan[i : i + MULTI_DOCUMENT_LIMIT]
    try:
        scan, status_code = client.multi_content_scan(chunk)
    except Exception as exc:
        # Handle exceptions such as schema validation
        traceback.print_exc(2, file=sys.stderr)
        print(str(exc))
    if status_code != 200:
        print("Error scanning some files. Results may be incomplete.")
    to_process.extend(scan)

for scan_result in to_process:
    print("Scan results:", scan_result.has_secrets, "-", scan_result.policy_break_count)
