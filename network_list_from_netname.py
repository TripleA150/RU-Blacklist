#!/usr/bin/env python3

import argparse
import re
import sys

import requests

from pylib.ip import convert_to_cidr, sort_prefixes
from pylib.sources import iter_list_entries, read_source_lines, unique
from pylib.whois import whois_networks

NETNAME_PREFIX_RE = re.compile(r"^netname:", re.IGNORECASE)


def iter_netnames(lines):
    """Yield unique netnames from lines like 'NAME' or 'netname: NAME'; comments are skipped."""
    def names():
        for entry in iter_list_entries(lines):
            if NETNAME_PREFIX_RE.match(entry):
                entry = entry.split(":", 1)[1].strip()
            if entry:
                yield entry

    return unique(names())


def resolve_netname(netname):
    """Return sorted, de-duplicated CIDR prefixes registered under ``netname``."""
    networks = []
    for ip_range in whois_networks(netname):
        try:
            networks.extend(convert_to_cidr(ip_range))
        except ValueError as exc:
            print(f"WARNING: skipping malformed range {ip_range!r} for {netname}: {exc}", file=sys.stderr)
    return sort_prefixes(unique(networks))


def extract_netname(filename_or_url, quiet=False):
    for netname in iter_netnames(read_source_lines(filename_or_url)):
        networks = resolve_netname(netname)
        if not networks:
            continue
        if not quiet:
            print(f"# Network name: {netname}")
        for network in networks:
            print(network)


def build_parser():
    parser = argparse.ArgumentParser(description="Extract netname from file.")
    parser.add_argument("filename_or_url", help="The file or URL to extract netnames from.")
    parser.add_argument("-q", "--quiet", action="store_true", help="Disable all output except prefixes.")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        extract_netname(args.filename_or_url, quiet=args.quiet)
    except requests.RequestException as exc:
        print(f"ERROR: failed to fetch netname data: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"ERROR: failed to read input or query whois: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
