"""Runs the blacklists_updater_*.sh scripts on a throw-away copy of the repository."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent

AUTO = {
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
    for path in REPO.glob("*.sh"):
        shutil.copy2(path, tmp_path)
    for path in REPO.glob("*.py"):
        shutil.copy2(path, tmp_path)
    shutil.copy2(REPO / "blacklists_updater_common.subr", tmp_path)
    shutil.copytree(REPO / "pylib", tmp_path / "pylib", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(REPO / "lists", tmp_path / "lists")
    (tmp_path / "auto").mkdir()
    for name, lines in AUTO.items():
        (tmp_path / "auto" / name).write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")
    (tmp_path / "network_list_from_as.py").write_text(STUB_AS, encoding="utf-8")
    (tmp_path / "network_list_from_netname.py").write_text(STUB_NETNAME, encoding="utf-8")
    return tmp_path


def run(repo, script, **env):
    return subprocess.run(
        ["sh", str(repo / script)],
        cwd=repo,
        env={**os.environ, "PYTHON": sys.executable, **env},
        capture_output=True,
        text=True,
        check=False,
    )


def lines(path):
    return path.read_text(encoding="utf-8").splitlines()


def matches_black_names(repo, text):
    script = 'SCRIPT_DIR="$1"; . "$1/blacklists_updater_common.subr"; printf "%s\\n" "$2" | grep -qiE -- "${BLACK_NAMES}"'
    return subprocess.run(["sh", "-c", script, "sh", str(repo), text], check=False).returncode == 0


def test_black_names_match_whole_word_vk_as_only(repo):
    assert matches_black_names(repo, "AS47764 VK-AS (LLC VK)")
    assert not matches_black_names(repo, "AS43038 TVK-AS (MTS PJSC)")
    assert not matches_black_names(repo, "AS1 VK-ASN-TEST (Other)")
    assert matches_black_names(repo, "192.0.2.0/24 X [mail.ru]")
    assert not matches_black_names(repo, "192.0.2.0/24 X [mailXru]")


def test_pattern_file_without_patterns_is_an_error(repo):
    (repo / "lists" / "black-names.txt").write_text("# only comments\n\n", encoding="utf-8")
    result = run(repo, "blacklists_updater_txt.sh")
    assert result.returncode != 0
    assert "no patterns" in result.stderr


def test_txt_updater_builds_aggregated_filtered_lists(repo):
    (repo / "lists" / "allowlist.txt").write_text("78.108.199.0/24\n", encoding="utf-8")
    result = run(repo, "blacklists_updater_txt.sh")
    assert result.returncode == 0, result.stderr

    black_ass = lines(repo / "auto" / "black_ass.txt")
    assert "AS47764" in black_ass and "AS61280" in black_ass
    assert "AS43038" not in black_ass, "TVK-AS (MTS) must not be blacklisted"
    assert "AS50000" not in black_ass, "white-names must win"

    blacklist = lines(repo / "blacklists" / "blacklist.txt")
    assert "192.0.2.0/24" in blacklist, "adjacent /25s are collapsed"
    assert "78.108.192.0/22" in blacklist and "78.108.199.0/24" not in blacklist, "allowlist is cut out"
    assert "2a00:bdc0::/29" in blacklist, "IPv6 allocations are matched too"
    assert lines(repo / "blacklists" / "blacklist-v6.txt") == ["2a00:bdc0::/29"]
    assert "100.64.0.0/24" not in blacklist

    vk = lines(repo / "blacklists" / "blacklist-vk.txt")
    assert vk == ["87.240.128.0/18", "203.0.113.0/24", "2a00:bdc0::/29"]
    assert not list(repo.glob(".build.*")), "work dir is cleaned up"


def test_txt_updater_failure_keeps_published_files(repo):
    assert run(repo, "blacklists_updater_txt.sh").returncode == 0
    before = {p: p.read_bytes() for p in (repo / "blacklists").iterdir()}

    result = run(repo, "blacklists_updater_txt.sh", FAIL_NETNAME="1")

    assert result.returncode != 0
    assert {p: p.read_bytes() for p in (repo / "blacklists").iterdir()} == before


def test_format_generators_do_not_rewrite_unchanged_files(repo):
    assert run(repo, "blacklists_updater_txt.sh").returncode == 0
    scripts = [
        "blacklists_updater_nftables.sh",
        "blacklists_updater_iptables.sh",
        "blacklists_updater_nginx.sh",
        "blacklists_updater_routes.sh",
    ]
    for script in scripts:
        result = run(repo, script)
        assert result.returncode == 0, result.stderr

    outputs = [
        p for d in ("blacklists_nftables", "blacklists_iptables", "blacklists_nginx", "blacklists_route") for p in (repo / d).iterdir()
    ]
    assert len(outputs) == 15  # 6 nft + 4 ipset + 3 nginx + 2 routes
    stamps = {p: (p.stat().st_mtime_ns, p.read_bytes()) for p in outputs}

    for script in scripts:
        assert run(repo, script).returncode == 0
    assert {p: (p.stat().st_mtime_ns, p.read_bytes()) for p in outputs} == stamps

    ipset = lines(repo / "blacklists_iptables" / "blacklist-vk-v4.ipset")
    assert "add blacklist-vk-v4-tmp 87.240.128.0/18" in ipset
    assert ipset[-2:] == ["swap blacklist-vk-v4-tmp blacklist-vk-v4", "destroy blacklist-vk-v4-tmp"]
    assert "flush set inet filter blacklist_vk_v6" in (repo / "blacklists_nftables" / "blacklist-vk-v6.nft").read_text(encoding="utf-8")


def test_custom_asns_and_prefixes_are_added(repo):
    with open(repo / "lists" / "custom-blacklist.txt", "a", encoding="utf-8") as custom:
        custom.write("as64500  # my ASN\n198.51.100.7  # one host\n2001:db8:1::/48\n")

    result = run(repo, "blacklists_updater_txt.sh")
    assert result.returncode == 0, result.stderr

    assert "AS64500" in lines(repo / "auto" / "black_ass.txt")
    blacklist = lines(repo / "blacklists" / "blacklist.txt")
    assert {"198.18.0.0/24", "198.51.100.7/32", "2001:db8:1::/48"} <= set(blacklist)
    assert not set(lines(repo / "blacklists" / "blacklist-vk.txt")) & {"198.18.0.0/24", "198.51.100.7/32"}


def test_invalid_custom_entry_fails_the_build(repo):
    with open(repo / "lists" / "custom-blacklist.txt", "a", encoding="utf-8") as custom:
        custom.write("AS 64500\n")
    assert run(repo, "blacklists_updater_txt.sh").returncode != 0


@pytest.mark.parametrize("name", ["black-names.txt", "vk-names.txt"])
def test_invalid_pattern_fails_instead_of_matching_nothing(repo, name):
    with open(repo / "lists" / name, "a", encoding="utf-8") as patterns:
        patterns.write("broken(\n")
    result = run(repo, "blacklists_updater_txt.sh")
    assert result.returncode != 0
    assert not (repo / "blacklists" / "blacklist.txt").exists()
