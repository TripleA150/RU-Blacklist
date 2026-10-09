"""Checks the hand-edited files in config/, so a typo fails CI right after the push
instead of breaking the next scheduled build."""

import ipaddress
import re
import subprocess
from pathlib import Path

import pytest

LISTS = Path(__file__).resolve().parent.parent / "config"
ASN_RE = re.compile(r"AS\d+", re.IGNORECASE)


def entries(name):
    for lineno, line in enumerate((LISTS / name).read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            yield lineno, stripped.split()[0]


def is_prefix(token):
    try:
        ipaddress.ip_network(token, strict=False)
    except ValueError:
        return False
    return True


@pytest.mark.parametrize("name", ["custom-blacklist.txt"])
def test_custom_lists_contain_asns_or_prefixes(name):
    bad = [f"config/{name}:{lineno}: {token!r}" for lineno, token in entries(name) if not (ASN_RE.fullmatch(token) or is_prefix(token))]
    assert not bad, "entries must be an ASN (AS12345) or a prefix (203.0.113.0/24):\n" + "\n".join(bad)


def test_allowlist_contains_prefixes():
    bad = [f"config/allowlist.txt:{lineno}: {token!r}" for lineno, token in entries("allowlist.txt") if not is_prefix(token)]
    assert not bad, "allowlist entries must be prefixes:\n" + "\n".join(bad)


def patterns(name):
    return [
        line.strip()
        for line in (LISTS / name).read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


@pytest.mark.parametrize("name", ["black-names.txt", "white-names.txt"])
def test_grep_patterns_compile(name):
    assert patterns(name), f"config/{name} has no patterns"
    for pattern in patterns(name):
        result = subprocess.run(["grep", "-iE", "--", pattern], input="", capture_output=True, text=True, check=False)
        assert result.returncode in (0, 1), f"config/{name}: invalid pattern {pattern!r}: {result.stderr.strip()}"


def test_vk_patterns_compile():
    for pattern in patterns("vk-names.txt"):
        assert pattern == pattern.lower(), f"config/vk-names.txt: write patterns in lower case: {pattern!r}"
        result = subprocess.run(
            ["awk", 'BEGIN { if ("" ~ ENVIRON["P"]) {} }'], env={"P": pattern}, capture_output=True, text=True, check=False
        )
        assert result.returncode == 0, f"config/vk-names.txt: invalid pattern {pattern!r}: {result.stderr.strip()}"
