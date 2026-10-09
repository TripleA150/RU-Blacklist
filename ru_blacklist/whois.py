"""Minimal RIPE whois client.

All queries use the ``-r`` flag (no referenced person/role objects). Contact
objects count toward RIPE's daily personal-data limit, and shared CI runner IPs
hit that limit quickly, after which every answer is an access-denied error.
"""

import socket
import time
from functools import lru_cache

WHOIS_SERVER = "whois.ripe.net"
WHOIS_PORT = 43
NO_DESCRIPTION = "-no-description-"
NO_ORG_NAME = "No org name found"


class WhoisError(OSError):
    """The whois server refused the query (rate limit, ban) or kept failing."""


def _decode(raw):
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _check_errors(response):
    for line in response.splitlines():
        # %ERROR:101 means "no entries found" and is a normal empty answer.
        if line.startswith("%ERROR:") and not line.startswith("%ERROR:101"):
            raise WhoisError(line.strip())


def raw_query(query, server=WHOIS_SERVER, port=WHOIS_PORT, timeout=30, retries=3, backoff=2.0):
    """Send a query and return the decoded response, retrying on network errors."""
    last_error = None
    for attempt in range(retries):
        try:
            with socket.create_connection((server, port), timeout=timeout) as sock:
                sock.sendall(f"{query}\r\n".encode())
                chunks = []
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    chunks.append(data)
        except OSError as exc:
            last_error = exc
            if attempt + 1 < retries:
                time.sleep(backoff * (2**attempt))
            continue
        response = _decode(b"".join(chunks))
        _check_errors(response)
        return response
    raise WhoisError(f"whois query {query!r} failed after {retries} attempts: {last_error}")


def iter_attributes(response):
    """Yield (name, value) pairs of RPSL attributes, skipping comments and continuation lines."""
    for line in response.splitlines():
        if not line or line[0] in "%#" or line[0].isspace() or ":" not in line:
            continue
        name, value = line.split(":", 1)
        yield name.strip().lower(), value.strip()


def first_attribute(response, name):
    for attr, value in iter_attributes(response):
        if attr == name:
            return value
    return None


def all_attributes(response, *names):
    return [value for attr, value in iter_attributes(response) if attr in names]


@lru_cache(maxsize=4096)
def org_name(org_handle):
    """Resolve an organisation handle (ORG-XXX-RIPE) into its org-name."""
    response = raw_query(f"-r -T organisation {org_handle}")
    return first_attribute(response, "org-name")


def whois_query(query, get_field="netname", get_org=False):
    """Return a single attribute of the object found by ``query``.

    get_field="inetnum" returns the list of all inetnum values instead.
    get_org=True appends " (<org-name>)" resolved via the object's org: handle.
    """
    response = raw_query(f"-r {query}")
    if get_field == "inetnum":
        return all_attributes(response, "inetnum")

    value = first_attribute(response, get_field) or NO_DESCRIPTION
    if not get_org:
        return value

    handle = first_attribute(response, "org")
    name = org_name(handle) if handle else None
    return f"{value} ({name or NO_ORG_NAME})"


def whois_networks(netname):
    """Return inetnum ranges and inet6num prefixes registered under ``netname``."""
    response = raw_query(f"-r -T inetnum,inet6num {netname}")
    return all_attributes(response, "inetnum", "inet6num")
