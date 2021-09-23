import glob
import os
import sys
import traceback
from typing import List

from pygitguardian import GGClient
from pygitguardian.config import MULTI_DOCUMENT_LIMIT
from pygitguardian.models import Detail, ScanResult


API_KEY = os.getenv("GITGUARDIAN_API_KEY", "")

client = GGClient(api_key=API_KEY)

# Create a list of dictionaries for scanning
to_scan = []
for name in glob.glob("**/*", recursive=True):
    with open(name) as fn:
        to_scan.append({"document": fn.read(), "filename": os.path.basename(name)})

# Process in a chunked way to avoid passing the multi document limit
to_process: List[ScanResult] = []
for i in range(0, len(to_scan), MULTI_DOCUMENT_LIMIT):
    chunk = to_scan[i : i + MULTI_DOCUMENT_LIMIT]
    try:
        scan = client.multi_content_scan(chunk)
    except Exception as exc:
        # Handle exceptions such as schema validation
        traceback.print_exc(2, file=sys.stderr)
        print(str(exc))
    if isinstance(scan, Detail):
        print("Error scanning some files. Results may be incomplete.")
        print(scan)
        continue

    to_process.extend(scan.scan_results)
    continue

for i, scan_result in enumerate(to_process):
    if scan_result.has_secrets:
        print(f"{chunk[i]['filename']}: {scan_result.policy_break_count} break/s found")
        for policy_break in scan_result.policy_breaks:
            print(f"\t{policy_break.break_type}:")
            for match in policy_break.matches:
                print(f"\t\t{match.match_type}:{match.match}")
