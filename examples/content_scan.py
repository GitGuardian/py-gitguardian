import os
import sys
import traceback

from requests import codes

from pygitguardian import GGClient
from pygitguardian.models import ScanResult


API_KEY = os.getenv("GITGUARDIAN_API_KEY", "")
FILENAME = ".env"
DOCUMENT = """
    import urllib.request
    url = 'http://jen_barber:correcthorsebatterystaple@cake.gitguardian.com/isreal.json'
    response = urllib.request.urlopen(url)
    consume(response.read())"
"""

client = GGClient(api_key=API_KEY)

# Check the health of the API and the API key used.
health_obj = client.health_check()

if health_obj.status_code == codes[r"\o/"]:  # this is 200 but cooler
    try:
        scan_result = client.content_scan(filename=FILENAME, document=DOCUMENT)
    except Exception as exc:
        # Handle exceptions such as schema validation
        traceback.print_exc(2, file=sys.stderr)
        print(str(exc))

    if isinstance(scan_result, ScanResult):
        print(
            "Scan results:",
            scan_result.has_secrets,
            "-",
            scan_result.policy_break_count,
        )
else:
    print("Invalid API Key")
