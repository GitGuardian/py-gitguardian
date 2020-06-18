<img src="https://cdn.jsdelivr.net/gh/gitguardian/py-gitguardian/doc/logo.svg">

# GitGuardian API Client

![Main](https://github.com/GitGuardian/py-gitguardian/workflows/Main/badge.svg)
[![GitHub license](https://img.shields.io/github/license/GitGuardian/py-gitguardian)](https://github.com/GitGuardian/py-gitguardian/blob/master/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/GitGuardian/py-gitguardian)](https://github.com/GitGuardian/py-gitguardian/stargazers)
[![CodeFactor](https://www.codefactor.io/repository/github/gitguardian/py-gitguardian/badge)](https://www.codefactor.io/repository/github/gitguardian/py-gitguardian)

API client library for the [GitGuardian API](https://api.gitguardian.com/).

The GitGuardian API puts at your fingertips the power to detect more than 200 types of secrets in any text content, as well as other potential security vulnerabilities.

**py-gitguardian** can be used to create integrations to scan various data sources, from your workstation's filesystem to your favorite chat application.

You can check API details [here](https://api.gitguardian.com/docs)
with all the response codes and expected structures on each method.

## Requirements

Python 3.5+

## Getting started

You can obtain API keys for API usage on your [dashboard](https://dashboard.gitguardian.com/api/v1/auth/user/github_login/authorize?utm_source=github&utm_medium=py_gitguardian&utm_campaign=py1).

**pip**

```bash
pip3 install --upgrade pygitguardian
```

**pipenv**

```bash
pipenv install pygitguardian
```

**poetry**

```bash
poetry add pygitguardian
```

## Examples

Check [examples/](examples/) for full examples on how to use py-gitguardian.

### Scanning text content

```py
# please don't hardcode your gg_api_key in source code :)
API_KEY = os.getenv("GG_API_KEY")
DOCUMENT = """
    import urllib.request
    url = 'http://jen_barber:correcthorsebatterystaple@cake.gitguardian.com/isreal.json'
    response = urllib.request.urlopen(url)
    consume(response.read())"
"""

client = GGClient(api_key=API_KEY)

# Check the health of the API and the API key used.
if client.health_check().success:
    try:
        scan_result = client.content_scan(DOCUMENT)
    except Exception as exc:
        # Handle exceptions such as schema validation
        traceback.print_exc(2, file=sys.stderr)
        print(str(exc))
        print(scan_result)
else:
    print("Invalid API Key")
```

### Scanning multiple files

```py
API_KEY = os.getenv("GG_API_KEY")
client = GGClient(api_key=API_KEY)
# Create a list of dictionaries for scanning
to_scan = []
for name in glob.glob("**/*", recursive=True):
    with open(name) as fn:
        to_scan.append({"document": fn.read(), "filename": os.path.basename(name)})

scan = client.multi_content_scan(to_scan)
```

### Transform results to dict or JSON

Any model in `py-gitguardian` can be turned to a JSON string or a dictionary using
the `to_dict` and `to_json` methods.

```py
from pygitguardian.models import Detail

detail = Detail("Invalid API Key.")
print(detail.to_dict())
print(detail.to_json())
```

### Dependencies

Py-gitguardian depends on these excellent libraries:

- `requests` - HTTP client
- `marshmallow` - Request (de)serialization and input validation
