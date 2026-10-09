import ipaddress

import pytest

import aggregate_prefixes
import diff_blacklists
from pylib.ip import convert_to_cidr, sort_prefixes
from pylib.prefixes import aggregate, intervals, parse_prefix_lines, subtract_intervals


def nets(*items):
    return [ipaddress.ip_network(item) for item in items]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("10.0.0.0 - 10.0.0.255", ["10.0.0.0/24"]),
        ("10.0.0.0-10.0.1.127", ["10.0.0.0/24", "10.0.1.0/25"]),
        ("2001:db8::/32", ["2001:db8::/32"]),
        ("192.0.2.1", ["192.0.2.1/32"]),
    ],
)
def test_convert_to_cidr(value, expected):
    assert convert_to_cidr(value) == expected


@pytest.mark.parametrize("value", ["10.0.0.9 - 10.0.0.1", "10.0.0.0 - 2001:db8::1", "not-an-ip"])
def test_convert_to_cidr_rejects_bad_ranges(value):
    with pytest.raises(ValueError):
        convert_to_cidr(value)


def test_sort_prefixes_is_numeric_and_keeps_invalid_last():
    assert sort_prefixes(["2001:db8::/32", "10.0.0.0/8", "9.0.0.0/8", "junk"]) == ["9.0.0.0/8", "10.0.0.0/8", "2001:db8::/32", "junk"]


def test_parse_prefix_lines_takes_first_token_and_skips_comments():
    networks, invalid = parse_prefix_lines(["# comment", "", "10.0.0.0/24 NET-NAME (Org)", "AS123", "2001:db8::/48 # x"])
    assert [str(n) for n in networks] == ["10.0.0.0/24", "2001:db8::/48"]
    assert invalid == [(4, "AS123")]


def test_aggregate_collapses_and_sorts_ipv4_first():
    result = aggregate(nets("2001:db8::/33", "10.0.1.0/24", "2001:db8:8000::/33", "10.0.0.0/24", "10.0.0.0/25"))
    assert [str(n) for n in result] == ["10.0.0.0/23", "2001:db8::/32"]


def test_aggregate_cuts_out_excluded_ranges():
    result = aggregate(nets("10.0.0.0/22"), exclude=nets("10.0.1.0/24", "192.0.2.0/24"))
    assert [str(n) for n in result] == ["10.0.0.0/24", "10.0.2.0/23"]


def test_aggregate_drops_fully_excluded_networks():
    assert aggregate(nets("10.0.0.0/24"), exclude=nets("10.0.0.0/16")) == []


def test_subtract_intervals():
    left = [[0, 100], [200, 300]]
    right = [[10, 20], [90, 210], [300, 400]]
    assert subtract_intervals(left, right) == [[0, 9], [21, 89], [211, 299]]


def test_intervals_merge_adjacent():
    assert intervals(nets("10.0.0.0/25", "10.0.0.128/25"), 4) == [
        [int(ipaddress.ip_address("10.0.0.0")), int(ipaddress.ip_address("10.0.0.255"))]
    ]


def test_aggregate_cli(tmp_path, capsys):
    source = tmp_path / "in.txt"
    source.write_text("# x\n10.0.0.0/24\n10.0.1.0/24\n2001:db8::/32\n", encoding="utf-8")
    allow = tmp_path / "allow.txt"
    allow.write_text("10.0.1.0/25\n", encoding="utf-8")
    out = tmp_path / "out.txt"

    assert aggregate_prefixes.main([str(source), "--exclude", str(allow), "--family", "4", "-o", str(out)]) == 0
    assert out.read_text(encoding="utf-8").splitlines() == ["10.0.0.0/24", "10.0.1.128/25"]


def test_aggregate_cli_strict_and_min_entries(tmp_path):
    source = tmp_path / "in.txt"
    source.write_text("10.0.0.0/24\ngarbage\n", encoding="utf-8")
    out = tmp_path / "out.txt"
    assert aggregate_prefixes.main([str(source), "--strict", "-o", str(out)]) == 2
    assert aggregate_prefixes.main([str(source), "--min-entries", "5", "-o", str(out)]) == 3
    assert not out.exists()


def test_diff_reports_coverage_not_entry_count(tmp_path):
    old = tmp_path / "old.txt"
    new = tmp_path / "new.txt"
    old.write_text("10.0.0.0/25\n10.0.0.128/25\n192.0.2.0/24\n", encoding="utf-8")
    new.write_text("10.0.0.0/24\n198.51.100.0/24\n", encoding="utf-8")

    stats = diff_blacklists.compare(diff_blacklists.read_networks(str(old)), diff_blacklists.read_networks(str(new)))[4]
    assert (stats["old_entries"], stats["new_entries"]) == (3, 2)
    assert [str(n) for n in stats["removed"]] == ["192.0.2.0/24"]
    assert [str(n) for n in stats["added"]] == ["198.51.100.0/24"]
    assert stats["shrink"] == pytest.approx(0.5)


def test_diff_guard_and_summary(tmp_path):
    old = tmp_path / "old.txt"
    new = tmp_path / "new.txt"
    summary = tmp_path / "summary.md"
    old.write_text("10.0.0.0/16\n", encoding="utf-8")
    new.write_text("10.0.0.0/17\n", encoding="utf-8")

    assert diff_blacklists.main([str(old), str(new), "--max-shrink", "0.6", "--summary", str(summary)]) == 0
    assert diff_blacklists.main([str(old), str(new), "--max-shrink", "0.25"]) == diff_blacklists.EXIT_SHRINK
    assert "10.0.128.0/17" in summary.read_text(encoding="utf-8")


def test_diff_missing_old_file_counts_as_empty(tmp_path):
    new = tmp_path / "new.txt"
    new.write_text("10.0.0.0/24\n", encoding="utf-8")
    assert diff_blacklists.main([str(tmp_path / "missing.txt"), str(new), "--max-shrink", "0"]) == 0
