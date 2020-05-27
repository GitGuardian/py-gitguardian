import os
import sys
import traceback

from requests import codes

from pygitguardian import GGClient


API_KEY = os.getenv("GG_API_KEY")
FILENAME = ".env"
DOCUMENT = """
    import urllib.request
    url = 'http://jen_barber:correcthorsebatterystaple@cake.gitguardian.com/isreal.json'
    response = urllib.request.urlopen(url)
    consume(response.read())"
"""

client = GGClient(token=API_KEY)

# Check the health of the API and the token used.
health_obj, status = client.health_check()

if status == codes[r"\o/"]:  # this is 200 but cooler
    try:
        scan_result = client.content_scan(filename=FILENAME, document=DOCUMENT)
    except Exception as exc:
        # Handle exceptions such as schema validation
        traceback.print_exc(2, file=sys.stderr)
        print(str(exc))

    print("Scan results:", scan_result.has_secrets, "-", scan_result.policy_break_count)
else:
    print("Invalid API Key")
