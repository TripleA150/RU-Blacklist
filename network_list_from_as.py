#!/usr/bin/env python3

import argparse
import re
import sys

import requests

from pylib.ip import sort_prefixes
from pylib.sources import is_url, iter_list_entries, read_source_lines, ripestat, unique
from pylib.whois import whois_query

ASN_RE = re.compile(r"\bAS\d+\b", re.IGNORECASE)


def get_as_prefixes(asn):
    data = ripestat("announced-prefixes", resource=asn)
    return sort_prefixes(unique(prefix["prefix"] for prefix in data["prefixes"]))


def normalize_asn(value):
    match = ASN_RE.search(value)
    if match:
        return match.group(0).upper()
    return None


def print_prefixes(asn, quiet=False):
    normalized_asn = normalize_asn(asn)
    if normalized_asn is None:
        return

    if not quiet:
        print(f"# Networks announced by {normalized_asn}")
        info = whois_query(normalized_asn, "as-name", True).strip()
        print(f"# AS-Name (ORG): {info}")
    for prefix in get_as_prefixes(normalized_asn):
        print(prefix)


def iter_asns(lines):
    """Yield unique ASNs from list lines; comment lines (e.g. '# AS-Name: AS123 ...') are skipped."""
    return unique(asn for asn in map(normalize_asn, iter_list_entries(lines)) if asn)


def extract_asses(asn_filename_or_url, quiet=False):
    if normalize_asn(asn_filename_or_url) and not is_url(asn_filename_or_url):
        print_prefixes(asn_filename_or_url, quiet=quiet)
        return

    for asn in iter_asns(read_source_lines(asn_filename_or_url)):
        print_prefixes(asn, quiet=quiet)


def build_parser():
    parser = argparse.ArgumentParser(description="./network_list_from_as.py -q AS61280")
    parser.add_argument("asn_filename_or_url", help="The AS number to get networks / The file or URL to extract AS numbers from.")
    parser.add_argument("-q", "--quiet", action="store_true", help="Disable all output except prefixes.")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        extract_asses(args.asn_filename_or_url, quiet=args.quiet)
    except requests.RequestException as exc:
        print(f"ERROR: failed to fetch ASN data: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"ERROR: failed to read input or query whois: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
