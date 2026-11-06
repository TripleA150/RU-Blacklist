"""
python3 -m ru_blacklist.rules config/rules.txt KIND
Parses config/rules.txt (format described at the top of that file), checks every
line and prints the values of one kind of rule, one per line. Kinds: name, !name,
netname, asn, prefix, allow, ptr, ptr-key.
"""

import ipaddress
import re
import sys

KEYWORDS = ("name", "!name", "netname", "ptr", "ptr-key")
ASN_RE = re.compile(r"AS\d+", re.IGNORECASE)


def is_prefix(token):
    try:
        ipaddress.ip_network(token, strict=False)
    except ValueError:
        return False
    return True


def parse_line(line):
    """Return (kind, value) for a rule line, None for blank/comment lines; ValueError if invalid."""
    text = re.sub(r"\s+#.*$", "", line.strip())
    if not text or text.startswith("#"):
        return None
    word, _, rest = text.partition(" ")
    if word in KEYWORDS:
        value = rest.strip()
        if not value:
            raise ValueError(f"{word!r} needs a value")
        if word == "ptr-key":
            re.compile(value)
        if word == "ptr" and not (ASN_RE.fullmatch(value) or is_prefix(value)):
            raise ValueError(f"ptr needs a prefix or an ASN, got {value!r}")
        return word, value
    if ASN_RE.fullmatch(word):
        return "asn", word.upper()
    if word.startswith("!") and is_prefix(word[1:]):
        return "allow", word[1:]
    if is_prefix(word):
        return "prefix", word
    raise ValueError(f"unknown rule {text!r}")


def parse(lines):
    """Return a list of (kind, value); raises ValueError naming the bad line."""
    rules = []
    for lineno, line in enumerate(lines, start=1):
        try:
            rule = parse_line(line)
        except (ValueError, re.error) as exc:
            raise ValueError(f"line {lineno}: {exc}") from exc
        if rule:
            rules.append(rule)
    return rules


def main(argv=None):
    path, kind = (argv or sys.argv[1:])[:2]
    try:
        with open(path, encoding="utf-8") as file:
            rules = parse(file)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {path}: {exc}", file=sys.stderr)
        return 1
    sys.stdout.writelines(f"{value}\n" for rule_kind, value in rules if rule_kind == kind)
    return 0


if __name__ == "__main__":
    sys.exit(main())
