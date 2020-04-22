<img src="./doc/logo.svg">

# GitGuardian API Client

API client library for the GitGuardian API.

You can check API details [here](https://api.gitguardian.com/doc)
with all the response codes and expected structures on each method.

## Requirements

Python 3.5+

## Getting started

You can obtain tokens for API usage on your [dashboard](https://dashboard.gitguardian.com/api).

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

Check [examples/content_scan.py](examples/content_scan.py) for an example usage of the API.

### Dependencies

Py-gitguardian depends on these excelent libraries:

- `requests` - HTTP client
- `marshmallow` - Request (de)serialization and input validation
