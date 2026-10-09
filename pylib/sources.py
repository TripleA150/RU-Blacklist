"""HTTP access with retries and helpers for reading list files or URLs."""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

USER_AGENT = "RU-Blacklist (+https://github.com/TripleA150/RU-Blacklist)"
RIPESTAT_SOURCEAPP = "ru-blacklist"
DEFAULT_TIMEOUT = 60

_session = None


def session():
    global _session
    if _session is None:
        retry = Retry(
            total=5,
            backoff_factor=2,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("GET",),
            respect_retry_after_header=True,
        )
        _session = requests.Session()
        _session.headers["User-Agent"] = USER_AGENT
        _session.mount("https://", HTTPAdapter(max_retries=retry))
        _session.mount("http://", HTTPAdapter(max_retries=retry))
    return _session


def http_get(url, params=None, timeout=DEFAULT_TIMEOUT):
    response = session().get(url, params=params, timeout=timeout)
    response.raise_for_status()
    return response


def ripestat(endpoint, **params):
    """Call a RIPEstat data API endpoint and return its ``data`` payload."""
    params.setdefault("sourceapp", RIPESTAT_SOURCEAPP)
    payload = http_get(f"https://stat.ripe.net/data/{endpoint}/data.json", params=params).json()
    if payload.get("status") not in (None, "ok"):
        raise requests.RequestException(f"RIPEstat {endpoint} returned status {payload.get('status')!r}")
    return payload["data"]


def is_url(value):
    return value.startswith(("http://", "https://"))


def convert_to_raw_github_url(url):
    return url.replace("https://github.com/", "https://raw.githubusercontent.com/").replace("/blob/", "/", 1)


def read_source_lines(filename_or_url):
    """Read lines from a local file or URL (github.com blob links are converted to raw)."""
    if is_url(filename_or_url):
        if "github.com/" in filename_or_url:
            filename_or_url = convert_to_raw_github_url(filename_or_url)
        return http_get(filename_or_url).text.splitlines()
    with open(filename_or_url, encoding="utf-8") as file:
        return file.read().splitlines()


def iter_list_entries(lines):
    """Yield stripped, non-empty lines that are not comments."""
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            yield stripped


def unique(items):
    """De-duplicate while preserving the original order."""
    seen = set()
    for item in items:
        if item not in seen:
            seen.add(item)
            yield item
