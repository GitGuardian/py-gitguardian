import os
from os.path import dirname, join, realpath

import pytest
import vcr

from pygitguardian import GGClient


base_uri = os.environ.get("TEST_LIVE_SERVER_URL", "https://api.gitguardian.com")

my_vcr = vcr.VCR(
    cassette_library_dir=join(dirname(realpath(__file__)), "cassettes"),
    path_transformer=vcr.VCR.ensure_suffix(".yaml"),
    decode_compressed_response=True,
    ignore_localhost=True,
    match_on=["method", "url"],
    serializer="yaml",
    record_mode="once",
    filter_headers=["Authorization"],
)

if os.environ.get("TEST_LIVE_SERVER", "false").lower() == "true":
    my_vcr.record_mode = "all"


@pytest.fixture
def client():
    api_key = os.environ.get("TEST_LIVE_SERVER_TOKEN", "sample_api_key")
    return GGClient(base_uri=base_uri, api_key=api_key)
