"""Checks config/rules.txt, so a typo fails CI right after the push
instead of breaking the next scheduled build."""

import subprocess
from pathlib import Path

import pytest

from ru_blacklist import rules

RULES = Path(__file__).resolve().parent.parent / "config" / "rules.txt"


def test_rules_file_parses():
    parsed = rules.parse(RULES.read_text(encoding="utf-8").splitlines())
    assert any(kind == "name" for kind, _ in parsed), "config/rules.txt has no 'name' rules"


def test_name_patterns_compile_for_grep():
    for kind, pattern in rules.parse(RULES.read_text(encoding="utf-8").splitlines()):
        if kind in ("name", "!name"):
            result = subprocess.run(["grep", "-iE", "--", pattern], input="", capture_output=True, text=True, check=False)
            assert result.returncode in (0, 1), f"invalid {kind} pattern {pattern!r}: {result.stderr.strip()}"


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("name llc vk", ("name", "llc vk")),
        ("!name ruvds  # hosting", ("!name", "ruvds")),
        ("netname SPEZSVYAZ", ("netname", "SPEZSVYAZ")),
        ("as64500 # mine", ("asn", "AS64500")),
        ("203.0.113.7", ("prefix", "203.0.113.7")),
        ("!203.0.113.0/24", ("allow", "203.0.113.0/24")),
        ("ptr AS20764", ("ptr", "AS20764")),
        ("ptr-key (^|[.-])tspu", ("ptr-key", "(^|[.-])tspu")),
        ("# comment", None),
        ("", None),
    ],
)
def test_parse_line(line, expected):
    assert rules.parse_line(line) == expected


@pytest.mark.parametrize("line", ["nmae fsin", "AS 64500", "ptr example.com", "ptr-key tspu(", "name"])
def test_parse_line_rejects_typos(line):
    with pytest.raises(ValueError):
        rules.parse([line])
