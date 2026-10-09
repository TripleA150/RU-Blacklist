"""
python3 -m ru_blacklist.diff
Compares two versions of a prefix list by covered address space, prints what was
added/removed and fails if too much coverage disappeared at once (e.g. because an
upstream API returned partial data). Used by CI before publishing new lists.
Usage:
  python3 -m ru_blacklist.diff old/blacklist.txt output/txt/blacklist.txt --max-shrink 0.25
  git show HEAD:output/txt/blacklist.txt | python3 -m ru_blacklist.diff - output/txt/blacklist.txt --summary "$GITHUB_STEP_SUMMARY"
"""

import argparse
import sys
from pathlib import Path

from .prefixes import interval_size, intervals, intervals_to_networks, parse_prefix_lines, subtract_intervals

# IPv6 space is reported in /48 blocks to keep the numbers readable.
UNITS = {4: ("addresses", 0), 6: ("/48 blocks", 80)}
EXIT_SHRINK = 3


def read_networks(path):
    if path == "-":
        lines = sys.stdin.read().splitlines()
    else:
        p = Path(path)
        lines = p.read_text(encoding="utf-8").splitlines() if p.exists() else []
    networks, _ = parse_prefix_lines(lines)
    return networks


def compare(old, new):
    """Return per-version stats: entries, sizes and added/removed networks."""
    stats = {}
    for version in (4, 6):
        old_spans, new_spans = intervals(old, version), intervals(new, version)
        removed = subtract_intervals(old_spans, new_spans)
        added = subtract_intervals(new_spans, old_spans)
        old_size = interval_size(old_spans)
        stats[version] = {
            "old_entries": sum(1 for n in old if n.version == version),
            "new_entries": sum(1 for n in new if n.version == version),
            "old_size": old_size,
            "new_size": interval_size(new_spans),
            "removed": intervals_to_networks(removed, version),
            "added": intervals_to_networks(added, version),
            "shrink": interval_size(removed) / old_size if old_size else 0.0,
        }
    return stats


def _units(version, size):
    name, shift = UNITS[version]
    return f"{size >> shift} {name}"


def render_markdown(label, stats, max_list):
    out = [f"### {label}", "", "| | before | after | removed | added |", "|---|---:|---:|---:|---:|"]
    for version, s in stats.items():
        removed = sum(n.num_addresses for n in s["removed"])
        added = sum(n.num_addresses for n in s["added"])
        out.append(f"| IPv{version} prefixes | {s['old_entries']} | {s['new_entries']} | | |")
        out.append(
            f"| IPv{version} coverage | {_units(version, s['old_size'])} | {_units(version, s['new_size'])} "
            f"| {_units(version, removed)} ({s['shrink']:.1%}) | {_units(version, added)} |"
        )
    for kind in ("removed", "added"):
        nets = [n for s in stats.values() for n in s[kind]]
        if not nets:
            continue
        shown = "\n".join(str(n) for n in nets[:max_list])
        more = f"\n... and {len(nets) - max_list} more" if len(nets) > max_list else ""
        out += ["", f"<details><summary>{kind.capitalize()} ({len(nets)})</summary>", "", "```", shown + more, "```", "</details>"]
    out.append("")
    return "\n".join(out)


def build_parser():
    parser = argparse.ArgumentParser(description="Compare two prefix lists by covered address space.")
    parser.add_argument("old", help="Previous list ('-' for STDIN; a missing file counts as empty).")
    parser.add_argument("new", help="New list.")
    parser.add_argument("--label", help="Heading for the report (default: new file name).")
    parser.add_argument("--max-shrink", type=float, help="Fail if more than this fraction (0..1) of IPv4 or IPv6 coverage is removed.")
    parser.add_argument("--summary", help="Append a Markdown report to this file (e.g. $GITHUB_STEP_SUMMARY).")
    parser.add_argument("--max-list", type=int, default=50, help="Max prefixes listed per section in the report.")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    label = args.label or Path(args.new).name
    stats = compare(read_networks(args.old), read_networks(args.new))
    report = render_markdown(label, stats, args.max_list)
    print(report)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as summary:
            summary.write(report + "\n")

    if args.max_shrink is not None:
        for version, s in stats.items():
            if s["shrink"] > args.max_shrink:
                print(
                    f"ERROR: {label}: {s['shrink']:.1%} of IPv{version} coverage would be removed "
                    f"(limit {args.max_shrink:.0%}). Refusing to publish; re-run with the guard disabled if intended.",
                    file=sys.stderr,
                )
                return EXIT_SHRINK
    return 0


if __name__ == "__main__":
    sys.exit(main())
