"""Runs scripts/build.sh on a throw-away copy of the repository with stubbed network lookups."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent

DATA = {
    "all-ru-asn.txt": [
        "AS47764 VK-AS (LLC VK)",
        "AS43038 TVK-AS (MTS PJSC)",
        'AS61280 CMU_GRCHC-AS (FGUP "GRCHC")',
        "AS50000 RUVDS-AS (FGUP lookalike hosting)",
        "AS1 SOMETHING-ELSE (LLC Other)",
    ],
    "all-ru-ipv4.txt": [
        "87.240.128.0/18 RU-VKONTAKTE-20071018 (LLC VK)",
        "91.219.224.0/22 KZ-VKTECH-20101026 (VK Cloud Solutions VK Hosting)",
        "198.51.100.0/24 OTHER-NET (Other)",
    ],
    "all-ru-ipv6.txt": ["2a00:bdc0::/29 RU-VKONTAKTE-20071018 (LLC VK)"],
    "ripe-ru-ipv4.txt": [
        "192.0.2.0/25 CHUVD ROSTELECOM-MNT () [Regional Police Department]",
        "192.0.2.128/25 CHUVD2 ROSTELECOM-MNT () [Regional Police Department]",
        "203.0.113.0/24 ODNOKLASSNIKI-NET VKCOMPANY-MNT () []",
    ],
}

STUB_AS = """\
import sys
for line in open(sys.argv[1]):
    if line.startswith("AS"):
        print(f"# Networks announced by {line.strip()}")
        known = {"AS47764": "87.240.128.0/18", "AS61280": "185.224.228.0/24", "AS64500": "198.18.0.0/24", "AS64501": "198.19.0.0/24"}
        print(known.get(line.strip(), "100.64.0.0/24"))
"""

STUB_NETNAME = """\
import os, sys
if os.environ.get("FAIL_NETNAME"):
    sys.exit("whois is down")
print("# Network name: SPEZSVYAZ")
print("78.108.192.0/21")
"""


@pytest.fixture
def repo(tmp_path):
    shutil.copytree(REPO / "scripts", tmp_path / "scripts")
    shutil.copytree(REPO / "ru_blacklist", tmp_path / "ru_blacklist", ignore=shutil.ignore_patterns("__pycache__"))
    # Keep the real name patterns under test, but not your own ASNs, prefixes and PTR targets.
    kept = [line for line in lines(REPO / "config" / "rules.txt") if line.startswith(("name ", "!name "))]
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "rules.txt").write_text("\n".join([*kept, "ptr 80.64.96.0/20", "ptr-key tspu", ""]), encoding="utf-8")
    (tmp_path / "data").mkdir()
    for name, content in DATA.items():
        (tmp_path / "data" / name).write_text("".join(f"{line}\n" for line in content), encoding="utf-8")
    # The network lookups are replaced by stubs that answer from fixed tables.
    (tmp_path / "ru_blacklist" / "asn.py").write_text(STUB_AS, encoding="utf-8")
    (tmp_path / "ru_blacklist" / "netname.py").write_text(STUB_NETNAME, encoding="utf-8")
    (tmp_path / "ru_blacklist" / "ptr.py").write_text(
        'print("# PTR: 80.64.97.53 tspu-1.example")\nprint("80.64.97.53/32")\n', encoding="utf-8"
    )
    return tmp_path


def add_rules(repo, *new):
    with open(repo / "config" / "rules.txt", "a", encoding="utf-8") as rules:
        rules.writelines(f"{line}\n" for line in new)


def build(repo, *args, **env):
    return subprocess.run(
        ["sh", str(repo / "scripts" / "build.sh"), *args],
        cwd=repo,
        env={**os.environ, "PYTHON": sys.executable, **env},
        capture_output=True,
        text=True,
        check=False,
    )


def lines(path):
    return path.read_text(encoding="utf-8").splitlines()


def matches_black_names(repo, text):
    script = 'REPO_ROOT="$1"; . "$1/scripts/lib.sh"; printf "%s\\n" "$2" | grep -qiE -- "${BLACK_NAMES}"'
    return subprocess.run(["sh", "-c", script, "sh", str(repo), text], check=False).returncode == 0


def test_black_names_match_whole_word_vk_as_only(repo):
    assert matches_black_names(repo, "AS47764 VK-AS (LLC VK)")
    assert not matches_black_names(repo, "AS43038 TVK-AS (MTS PJSC)")
    assert not matches_black_names(repo, "AS1 VK-ASN-TEST (Other)")
    assert matches_black_names(repo, "192.0.2.0/24 X [mail.ru]")
    assert not matches_black_names(repo, "192.0.2.0/24 X [mailXru]")


def test_rules_without_name_patterns_are_an_error(repo):
    (repo / "config" / "rules.txt").write_text("# only comments\nAS64500\n", encoding="utf-8")
    result = build(repo)
    assert result.returncode != 0
    assert "no 'name' rules" in result.stderr


def test_build_makes_aggregated_filtered_lists(repo):
    add_rules(repo, "!78.108.199.0/24")
    result = build(repo)
    assert result.returncode == 0, result.stderr

    black_ass = lines(repo / "data" / "black_ass.txt")
    assert "AS47764" in black_ass and "AS61280" in black_ass
    assert "AS43038" not in black_ass, "TVK-AS (MTS) must not be blacklisted"
    assert "AS50000" not in black_ass, "!name must win"

    txt = repo / "output" / "txt"
    blacklist = lines(txt / "blacklist.txt")
    assert "192.0.2.0/24" in blacklist, "adjacent /25s are collapsed"
    assert "78.108.192.0/22" in blacklist and "78.108.199.0/24" not in blacklist, "!prefix is cut out"
    assert "2a00:bdc0::/29" in blacklist, "IPv6 allocations are matched too"
    assert "80.64.97.53/32" in blacklist, "PTR keyword matches are added"
    assert lines(txt / "blacklist-v6.txt") == ["2a00:bdc0::/29"]
    assert "100.64.0.0/24" not in blacklist
    assert not list(repo.glob(".build.*")), "work dir is cleaned up"


def test_failed_build_keeps_published_files(repo):
    assert build(repo).returncode == 0
    before = {p: p.read_bytes() for p in (repo / "output" / "txt").iterdir()}

    result = build(repo, FAIL_NETNAME="1")

    assert result.returncode != 0
    assert {p: p.read_bytes() for p in (repo / "output" / "txt").iterdir()} == before


def test_offline_rebuild_does_not_rewrite_unchanged_files(repo):
    assert build(repo).returncode == 0
    outputs = [p for d in ("nftables", "ipset") for p in (repo / "output" / d).iterdir()]
    assert len(outputs) == 5  # 3 nft + 2 ipset
    stamps = {p: (p.stat().st_mtime_ns, p.read_bytes()) for p in outputs}

    result = build(repo, "--offline", FAIL_NETNAME="1")  # no network lookups in offline mode
    assert result.returncode == 0, result.stderr
    assert {p: (p.stat().st_mtime_ns, p.read_bytes()) for p in outputs} == stamps

    ipset = lines(repo / "output" / "ipset" / "blacklist-v4.ipset")
    assert "add blacklist-v4-tmp 87.240.128.0/18" in ipset
    assert ipset[-2:] == ["swap blacklist-v4-tmp blacklist-v4", "destroy blacklist-v4-tmp"]
    assert "flush set inet filter blacklist_v6" in (repo / "output" / "nftables" / "blacklist-v6.nft").read_text(encoding="utf-8")


def test_custom_asns_and_prefixes_are_added(repo):
    add_rules(repo, "as64500  # my ASN", "198.51.100.7  # one host", "2001:db8:1::/48")
    result = build(repo)
    assert result.returncode == 0, result.stderr

    assert "AS64500" in lines(repo / "data" / "black_ass.txt")
    assert {"198.18.0.0/24", "198.51.100.7/32", "2001:db8:1::/48"} <= set(lines(repo / "output" / "txt" / "blacklist.txt"))


@pytest.mark.parametrize("rule", ["AS 64500", "nmae fsin", "name broken("])
def test_bad_rule_fails_before_anything_is_written(repo, rule):
    add_rules(repo, rule)
    assert build(repo).returncode != 0
    assert not (repo / "output" / "txt" / "blacklist.txt").exists()
