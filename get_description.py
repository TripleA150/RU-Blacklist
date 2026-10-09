#!/usr/bin/env python3
"""
get_description.py
Fills in "<name> (<org-name>)" descriptions in auto/all-ru-*.txt style files
("<ASN or prefix> <description>" per line).

With --ripe-dump-dir the names are resolved offline from RIPE DB split dumps
(ripe.db.aut-num.gz, ripe.db.inetnum.gz, ripe.db.inet6num.gz, ripe.db.organisation.gz).
Whatever is still unresolved afterwards is looked up via whois, at most --limit queries.
Usage:
  get_description.py auto/all-ru-asn.txt --limit 500
  get_description.py --ripe-dump-dir /tmp/ripe --refresh auto/all-ru-asn.txt auto/all-ru-ipv4.txt auto/all-ru-ipv6.txt
"""

import argparse
import sys
from pathlib import Path

from pylib import ripedb
from pylib.files import write_atomic
from pylib.whois import NO_DESCRIPTION, NO_ORG_NAME, WhoisError, whois_query


def entry_kind(key):
    if key.upper().startswith("AS"):
        return "aut-num"
    return "inet6num" if ":" in key else "inetnum"


def read_entries(path):
    entries = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        parts = line.strip().split(None, 1)
        if parts:
            entries.append([parts[0], parts[1] if len(parts) > 1 else NO_DESCRIPTION])
    return entries


def is_unresolved(description):
    return description.startswith(NO_DESCRIPTION)


def completeness(description):
    """0 = nothing known, 1 = name only, 2 = name and organisation."""
    if is_unresolved(description):
        return 0
    return 1 if description.endswith(f"({NO_ORG_NAME})") else 2


def format_description(name, org_name):
    return f"{name or NO_DESCRIPTION} ({org_name or NO_ORG_NAME})"


class DumpResolver:
    """Lazily loads RIPE dumps; each dump is streamed at most once per kind of lookup."""

    def __init__(self, dump_dir):
        self.dump_dir = Path(dump_dir)
        self._org_names = None

    def _dump(self, object_class):
        path = self.dump_dir / ripedb.DUMP_FILES[object_class]
        if not path.exists():
            print(f"WARNING: {path} not found, skipping offline {object_class} lookups", file=sys.stderr)
            return None
        return path

    def org_names(self):
        if self._org_names is None:
            path = self._dump("organisation")
            self._org_names = ripedb.load_org_names(path) if path else {}
        return self._org_names

    def resolve(self, object_class, keys):
        """Return {key: description} for the keys found in the dump of ``object_class``."""
        path = self._dump(object_class)
        if path is None or not keys:
            return {}
        if object_class == "aut-num":
            found = ripedb.load_aut_nums(path, {key.upper() for key in keys})
            found = {key: found[key.upper()] for key in keys if key.upper() in found}
        else:
            found = ripedb.resolve_networks(path, object_class, keys)
        orgs = self.org_names()
        return {key: format_description(name, orgs.get((org or "").upper())) for key, (name, org) in found.items()}


def resolve_files(paths, dump_dir=None, refresh=False, whois_limit=0, verbose=False):
    files = {path: read_entries(path) for path in paths}
    stats = {"offline": 0, "whois": 0, "unresolved": 0}

    if dump_dir:
        resolver = DumpResolver(dump_dir)
        by_kind = {}
        for entries in files.values():
            for entry in entries:
                if refresh or is_unresolved(entry[1]):
                    by_kind.setdefault(entry_kind(entry[0]), []).append(entry)
        for object_class, entries in by_kind.items():
            resolved = resolver.resolve(object_class, [key for key, _ in entries])
            for entry in entries:
                description = resolved.get(entry[0])
                # Never replace a description with a less complete one.
                if description and completeness(description) >= max(completeness(entry[1]), 1):
                    stats["offline"] += entry[1] != description
                    entry[1] = description

    queries = 0
    for entries in files.values():
        for entry in entries:
            if not is_unresolved(entry[1]):
                continue
            if queries >= whois_limit:
                stats["unresolved"] += 1
                continue
            queries += 1
            field = "as-name" if entry_kind(entry[0]) == "aut-num" else "netname"
            try:
                description = whois_query(entry[0], field, True).strip()
            except WhoisError as exc:
                print(f"WARNING: whois failed ({exc}); stopping whois lookups", file=sys.stderr)
                whois_limit = queries
                stats["unresolved"] += 1
                continue
            if verbose:
                print(f"{entry[0]} {description}")
            if not is_unresolved(description):
                stats["whois"] += 1
            else:
                stats["unresolved"] += 1
            entry[1] = description

    for path, entries in files.items():
        write_atomic(path, [f"{key} {description}" for key, description in entries])
    return stats


def build_parser():
    parser = argparse.ArgumentParser(description="Resolve names for ASNs and Networks.")
    parser.add_argument("filenames", nargs="+", help="Files with lists of ASNs or Networks (one '<key> <description>' per line).")
    parser.add_argument("--ripe-dump-dir", help="Directory with RIPE DB split dumps for offline resolution.")
    parser.add_argument("--refresh", action="store_true", help="Re-resolve all entries from the dumps, not only missing ones.")
    parser.add_argument("--limit", type=int, default=2500,
                        help="Max whois queries for entries still unresolved (prevents blacklisting by whois servers).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print every whois result.")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        stats = resolve_files(args.filenames, args.ripe_dump_dir, args.refresh, args.limit, args.verbose)
    except OSError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Resolved offline: {stats['offline']}, via whois: {stats['whois']}, still unresolved: {stats['unresolved']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
