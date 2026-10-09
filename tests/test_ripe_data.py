import gzip

import pytest

import get_description
import get_info_from_ripe
from pylib import ripedb

AUT_NUM = """\
% RIPE dump

aut-num:        AS61280
as-name:        CMU_GRCHC-AS
remarks:        first line
                continuation line
org:            ORG-GRCHC1-RIPE

aut-num:        AS47764
as-name:        VK-AS
org:            org-vk1-ripe

aut-num:        AS100
as-name:        NO-ORG-AS
"""

ORGANISATION = """\
organisation:   ORG-GRCHC1-RIPE
org-name:       FGUP "GRCHC"

organisation:   ORG-VK1-RIPE
org-name:       LLC VK
"""

INETNUM = """\
inetnum:        0.0.0.0 - 255.255.255.255
netname:        IANA-BLK

inetnum:        2.56.24.0 - 2.56.27.255
netname:        RU-K-TELEKOM-20190313
org:            ORG-VK1-RIPE

inetnum:        2.56.24.0 - 2.56.24.255
netname:        SMALL-ASSIGNMENT

inetnum:        bogus
netname:        BROKEN
"""

INET6NUM = """\
inet6num:       2a00:bdc0::/29
netname:        RU-VKONTAKTE-20071018
org:            ORG-VK1-RIPE
"""


@pytest.fixture
def dump_dir(tmp_path):
    for object_class, content in (("aut-num", AUT_NUM), ("organisation", ORGANISATION), ("inetnum", INETNUM), ("inet6num", INET6NUM)):
        with gzip.open(tmp_path / ripedb.DUMP_FILES[object_class], "wt", encoding="latin-1") as dump:
            dump.write(content)
    return tmp_path


def test_iter_objects_reads_first_values_and_skips_continuations(dump_dir):
    objects = list(ripedb.iter_objects(dump_dir / "ripe.db.aut-num.gz", {"as-name", "remarks"}))
    assert objects[0] == {"_class": "aut-num", "_key": "AS61280", "as-name": "CMU_GRCHC-AS", "remarks": "first line"}
    assert len(objects) == 3


def test_load_aut_nums_filters_wanted(dump_dir):
    assert ripedb.load_aut_nums(dump_dir / "ripe.db.aut-num.gz", {"AS47764"}) == {"AS47764": ("VK-AS", "org-vk1-ripe")}


def test_resolve_networks_picks_most_specific_covering_object(dump_dir):
    found = ripedb.resolve_networks(dump_dir / "ripe.db.inetnum.gz", "inetnum", ["2.56.24.0/23", "2.56.24.0/24", "9.9.9.0/24"])
    assert found == {
        "2.56.24.0/23": ("RU-K-TELEKOM-20190313", "ORG-VK1-RIPE"),
        "2.56.24.0/24": ("SMALL-ASSIGNMENT", None),
        "9.9.9.0/24": ("IANA-BLK", None),
    }


def write_lines(path, lines):
    path.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")
    return path


def test_get_description_offline(dump_dir, tmp_path):
    asn = write_lines(
        tmp_path / "asn.txt",
        ["AS61280 -no-description- (No org name found)", "AS47764 -no-description-", "AS100 -no-description-", "AS1 Kept (Org)"],
    )
    v4 = write_lines(tmp_path / "v4.txt", ["2.56.24.0/23 -no-description-", "2.56.26.0/23 -no-description-"])
    v6 = write_lines(tmp_path / "v6.txt", ["2a00:bdc0::/29 -no-description-"])

    stats = get_description.resolve_files([asn, v4, v6], dump_dir=dump_dir, whois_limit=0)

    assert asn.read_text(encoding="utf-8").splitlines() == [
        'AS61280 CMU_GRCHC-AS (FGUP "GRCHC")',
        "AS47764 VK-AS (LLC VK)",
        "AS100 NO-ORG-AS (No org name found)",
        "AS1 Kept (Org)",
    ]
    assert v4.read_text(encoding="utf-8").splitlines() == [
        "2.56.24.0/23 RU-K-TELEKOM-20190313 (LLC VK)",
        "2.56.26.0/23 RU-K-TELEKOM-20190313 (LLC VK)",
    ]
    assert v6.read_text(encoding="utf-8").splitlines() == ["2a00:bdc0::/29 RU-VKONTAKTE-20071018 (LLC VK)"]
    assert stats == {"offline": 6, "whois": 0, "unresolved": 0}


def test_refresh_never_downgrades_a_description(dump_dir, tmp_path):
    asn = write_lines(tmp_path / "asn.txt", ["AS100 OLD-NAME (Old Org)", "AS61280 OLD (Org)"])
    get_description.resolve_files([asn], dump_dir=dump_dir, refresh=True, whois_limit=0)
    assert asn.read_text(encoding="utf-8").splitlines() == ["AS100 OLD-NAME (Old Org)", 'AS61280 CMU_GRCHC-AS (FGUP "GRCHC")']


def test_whois_fallback_respects_limit_and_stops_on_errors(tmp_path, monkeypatch):
    asn = write_lines(tmp_path / "asn.txt", ["AS1 -no-description-", "AS2 -no-description-", "AS3 -no-description-"])
    calls = []

    def fake_whois(key, field, get_org):
        calls.append(key)
        if key == "AS2":
            raise get_description.WhoisError("%ERROR:201: access denied")
        return f"{key}-NAME (Org)"

    monkeypatch.setattr(get_description, "whois_query", fake_whois)
    stats = get_description.resolve_files([asn], whois_limit=10)

    assert calls == ["AS1", "AS2"]
    assert asn.read_text(encoding="utf-8").splitlines() == ["AS1 AS1-NAME (Org)", "AS2 -no-description-", "AS3 -no-description-"]
    assert stats == {"offline": 0, "whois": 1, "unresolved": 2}


def test_get_info_from_ripe_keeps_known_descriptions(tmp_path, monkeypatch):
    write_lines(tmp_path / "all-ru-asn.txt", ["AS1 ONE (Org)", "AS2 -no-description-", "AS9 GONE (Org)"])
    resources = {"asn": ["1", "2", "3"], "ipv4": ["10.0.0.0/8"], "ipv6": ["2001:db8::/32"]}
    monkeypatch.setattr(get_info_from_ripe, "ripestat", lambda *a, **k: {"resources": resources})

    assert get_info_from_ripe.main(["--output-dir", str(tmp_path)]) == 0
    assert (tmp_path / "all-ru-asn.txt").read_text(encoding="utf-8").splitlines() == [
        "AS1 ONE (Org)",
        "AS2 -no-description-",
        "AS3 -no-description-",
    ]
    assert (tmp_path / "all-ru-ipv6.txt").read_text(encoding="utf-8") == "2001:db8::/32 -no-description-\n"


def test_get_info_from_ripe_refuses_empty_answers(tmp_path, monkeypatch):
    original = write_lines(tmp_path / "all-ru-asn.txt", ["AS1 ONE (Org)"]).read_text(encoding="utf-8")
    monkeypatch.setattr(get_info_from_ripe, "ripestat", lambda *a, **k: {"resources": {"asn": ["1"], "ipv4": [], "ipv6": []}})

    assert get_info_from_ripe.main(["--output-dir", str(tmp_path)]) == 1
    assert (tmp_path / "all-ru-asn.txt").read_text(encoding="utf-8") == original
