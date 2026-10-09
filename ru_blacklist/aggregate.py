"""
python3 -m ru_blacklist.aggregate
Validates, de-duplicates and collapses IP prefixes into the minimal CIDR list,
optionally removing allowlisted ranges.
Usage:
  python3 -m ru_blacklist.aggregate output/txt/blacklist_with_comments.txt -o output/txt/blacklist.txt
  python3 -m ru_blacklist.aggregate --family 4 --exclude config/allowlist.txt output/txt/blacklist.txt
  cat prefixes.txt | python3 -m ru_blacklist.aggregate
"""

import argparse
import sys
from pathlib import Path

from .files import write_atomic
from .prefixes import aggregate, parse_prefix_lines


def read_inputs(paths):
    if not paths:
        return sys.stdin.read().splitlines()
    lines = []
    for path in paths:
        lines.extend(Path(path).read_text(encoding="utf-8").splitlines())
    return lines


def build_parser():
    parser = argparse.ArgumentParser(description="Validate and collapse IP prefix lists.")
    parser.add_argument("inputs", nargs="*", help="Input files (default: STDIN). Only the first token of each line is used.")
    parser.add_argument("-o", "--output", help="Write result to this file atomically (default: STDOUT).")
    parser.add_argument("--family", choices=["4", "6"], help="Keep only IPv4 or IPv6 prefixes.")
    parser.add_argument("--exclude", action="append", default=[], help="File with prefixes that must never be listed.")
    parser.add_argument("--min-entries", type=int, default=0, help="Fail without writing if fewer prefixes remain.")
    parser.add_argument("--strict", action="store_true", help="Fail on lines that are not valid prefixes.")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        networks, invalid = parse_prefix_lines(read_inputs(args.inputs))
        excluded, invalid_excluded = parse_prefix_lines(read_inputs(args.exclude)) if args.exclude else ([], [])
    except OSError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    for lineno, token in invalid + invalid_excluded:
        print(f"WARNING: line {lineno}: not a prefix: {token!r}", file=sys.stderr)
    if args.strict and (invalid or invalid_excluded):
        return 2

    if args.family:
        networks = [n for n in networks if n.version == int(args.family)]
    result = aggregate(networks, excluded)

    if len(result) < args.min_entries:
        print(f"ERROR: only {len(result)} prefixes left, expected at least {args.min_entries}", file=sys.stderr)
        return 3

    lines = [str(n) for n in result]
    if args.output:
        write_atomic(args.output, lines)
    else:
        sys.stdout.writelines(f"{line}\n" for line in lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
