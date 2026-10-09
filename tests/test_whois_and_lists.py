import socket

import pytest

from ru_blacklist import asn, netname, whois

AUT_NUM = """\
% This is the RIPE Database query service.

aut-num:        AS47764
as-name:        VK-AS
org:            ORG-VK1-RIPE
remarks:        note: value with a colon
"""

ORGANISATION = """\
organisation:   ORG-VK1-RIPE
org-name:       LLC VK
"""

NETWORKS = """\
inetnum:        78.108.192.0 - 78.108.199.255
netname:        SPEZSVYAZ

inet6num:       2001:db8::/48
netname:        SPEZSVYAZ
"""


@pytest.fixture
def fake_whois(monkeypatch):
    """Replace raw_query with canned answers and record the queries."""
    queries = []
    answers = {}

    def raw_query(query, **_):
        queries.append(query)
        for key, answer in answers.items():
            if query.endswith(key):
                return answer
        return "%ERROR:101: no entries found\n"

    whois.org_name.cache_clear()
    monkeypatch.setattr(whois, "raw_query", raw_query)
    return queries, answers


def test_whois_query_uses_no_referenced_flag_and_resolves_org(fake_whois):
    queries, answers = fake_whois
    answers.update({"AS47764": AUT_NUM, "ORG-VK1-RIPE": ORGANISATION})

    assert whois.whois_query("AS47764", "as-name", True) == "VK-AS (LLC VK)"
    assert queries == ["-r AS47764", "-r -T organisation ORG-VK1-RIPE"]


def test_whois_query_without_match(fake_whois):
    assert whois.whois_query("AS1", "as-name", True) == f"{whois.NO_DESCRIPTION} ({whois.NO_ORG_NAME})"
    assert whois.whois_query("AS1", "as-name") == whois.NO_DESCRIPTION


def test_attribute_values_keep_colons():
    assert whois.first_attribute(AUT_NUM, "remarks") == "note: value with a colon"


def test_whois_networks_returns_ipv4_and_ipv6(fake_whois):
    queries, answers = fake_whois
    answers["SPEZSVYAZ"] = NETWORKS
    assert whois.whois_networks("SPEZSVYAZ") == ["78.108.192.0 - 78.108.199.255", "2001:db8::/48"]
    assert queries == ["-r -T inetnum,inet6num SPEZSVYAZ"]


class FakeSocket:
    def __init__(self, payload):
        self.chunks = [payload, b""]
        self.sent = b""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def sendall(self, data):
        self.sent += data

    def recv(self, _):
        return self.chunks.pop(0)


def test_raw_query_raises_on_access_denied(monkeypatch):
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: FakeSocket(b"%ERROR:201: access denied for 192.0.2.1\n"))
    with pytest.raises(whois.WhoisError):
        whois.raw_query("AS1")


def test_raw_query_retries_network_errors(monkeypatch):
    attempts = []

    def connect(*_, **__):
        attempts.append(1)
        if len(attempts) < 3:
            raise ConnectionResetError("reset")
        return FakeSocket("as-name: ÄÖ\n".encode())

    monkeypatch.setattr(socket, "create_connection", connect)
    monkeypatch.setattr(whois.time, "sleep", lambda _: None)
    assert whois.raw_query("AS1") == "as-name: ÄÖ\n"
    assert len(attempts) == 3


def test_raw_query_gives_up(monkeypatch):
    def connect(*_, **__):
        raise TimeoutError("timeout")

    monkeypatch.setattr(socket, "create_connection", connect)
    monkeypatch.setattr(whois.time, "sleep", lambda _: None)
    with pytest.raises(whois.WhoisError):
        whois.raw_query("AS1", retries=2)


def test_asn_list_skips_comment_lines_and_duplicates():
    lines = ["# AS-Name: AS28709 VKONTAKTE-REGIONAL-CDN (LLC VK)", "AS28709", "as47764 extra", "AS28709", ""]
    assert list(asn.iter_asns(lines)) == ["AS28709", "AS47764"]


def test_extract_asses_queries_each_asn_once(tmp_path, monkeypatch, capsys):
    source = tmp_path / "black_ass.txt"
    source.write_text("# AS-Name: AS28709 X (LLC VK)\nAS28709\n# AS-Name: AS47764 VK-AS (LLC VK)\nAS47764\n", encoding="utf-8")
    calls = []
    monkeypatch.setattr(asn, "whois_query", lambda asn, *a: f"{asn}-NAME (Org)")

    def fake_ripestat(endpoint, resource):
        calls.append(resource)
        return {"prefixes": [{"prefix": "87.240.128.0/18"}, {"prefix": "5.61.16.0/21"}, {"prefix": "5.61.16.0/21"}]}

    monkeypatch.setattr(asn, "ripestat", fake_ripestat)
    asn.extract_asses(str(source))

    assert calls == ["AS28709", "AS47764"]
    out = capsys.readouterr().out.splitlines()
    assert out[:4] == ["# Networks announced by AS28709", "# AS-Name (ORG): AS28709-NAME (Org)", "5.61.16.0/21", "87.240.128.0/18"]


def test_netnames_are_deduplicated():
    lines = ["# comment", "netname: RSNET", "RSNET", "netname:SPEZSVYAZ", ""]
    assert list(netname.iter_netnames(lines)) == ["RSNET", "SPEZSVYAZ"]


def test_resolve_netname_converts_and_sorts(monkeypatch, capsys):
    monkeypatch.setattr(
        netname,
        "whois_networks",
        lambda name: ["78.108.200.0 - 78.108.200.255", "2001:db8::/48", "78.108.192.0 - 78.108.199.255", "bad - range"],
    )
    assert netname.resolve_netname("SPEZSVYAZ") == ["78.108.192.0/21", "78.108.200.0/24", "2001:db8::/48"]
    assert "skipping malformed range" in capsys.readouterr().err
