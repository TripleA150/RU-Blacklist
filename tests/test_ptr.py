import ipaddress
import re

import pytest

from ru_blacklist import ptr

NAMES = {
    "80.64.97.53": "tspu-6364.no-hope.msk-m9-cr5.ae666-3001.rascom.as20764.net",
    "80.64.97.54": "core1.rascom.as20764.net",
}


def test_finds_addresses_whose_ptr_matches_keywords():
    networks = [ipaddress.ip_network("80.64.97.52/30")]
    found = list(ptr.find_matches(networks, re.compile("tspu", re.IGNORECASE), resolve=NAMES.get))
    assert found == [("80.64.97.53", NAMES["80.64.97.53"])]


def test_scan_list_accepts_prefixes_and_asns_and_skips_ipv6(monkeypatch):
    monkeypatch.setattr(ptr, "get_as_prefixes", lambda asn: ["198.51.100.0/24", "2001:db8::/32"])
    networks = ptr.scan_networks(["# comment", "AS20764 rascom", "80.64.96.0/20"])
    assert [str(n) for n in networks] == ["80.64.96.0/20", "198.51.100.0/24"]


def test_refuses_huge_scans():
    with pytest.raises(ValueError):
        list(ptr.find_matches([ipaddress.ip_network("10.0.0.0/8")], re.compile("tspu")))
