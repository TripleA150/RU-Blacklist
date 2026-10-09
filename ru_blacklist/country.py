"""Fetch all ASNs and prefixes of a country from RIPEstat into data/all-ru-*.txt.

Descriptions already present in the existing files are kept for entries that
are still listed, so a refresh never throws away earlier resolution work.
New entries get "-no-description-" and are filled in by ru_blacklist.describe.
"""

import argparse
import sys
from pathlib import Path

import requests

from .files import write_atomic
from .sources import ripestat
from .whois import NO_DESCRIPTION

LISTS = (
    # (resource key, file name, key prefix)
    ("asn", "all-ru-asn.txt", "AS"),
    ("ipv4", "all-ru-ipv4.txt", ""),
    ("ipv6", "all-ru-ipv6.txt", ""),
)


def load_descriptions(path):
    descriptions = {}
    if not path.exists():
        return descriptions
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and not parts[1].startswith(NO_DESCRIPTION):
            descriptions[parts[0]] = parts[1]
    return descriptions


def update_list(path, keys):
    descriptions = load_descriptions(path)
    lines = [f"{key} {descriptions.get(key, NO_DESCRIPTION)}" for key in keys]
    write_atomic(path, lines)
    kept = sum(1 for key in keys if key in descriptions)
    print(f"{path}: {len(keys)} entries ({kept} descriptions kept, {len(keys) - kept} to resolve)")


def build_parser():
    parser = argparse.ArgumentParser(description="Fetch country ASNs/prefixes from RIPEstat.")
    parser.add_argument("--country", default="RU", help="ISO country code (default: RU).")
    parser.add_argument("--output-dir", default="data", type=Path, help="Directory for all-ru-*.txt (default: data).")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        resources = ripestat("country-resource-list", resource=args.country, v4_format="prefix")["resources"]
    except (requests.RequestException, KeyError, ValueError) as exc:
        print(f"ERROR: failed to fetch country resources: {exc}", file=sys.stderr)
        return 1

    updates = []
    for key, file_name, prefix in LISTS:
        keys = [f"{prefix}{str(item).strip()}" for item in resources.get(key, [])]
        if not keys:
            print(f"ERROR: RIPEstat returned no '{key}' resources, refusing to overwrite {file_name}", file=sys.stderr)
            return 1
        updates.append((args.output_dir / file_name, keys))

    for path, keys in updates:
        update_list(path, keys)
    return 0


if __name__ == "__main__":
    sys.exit(main())
