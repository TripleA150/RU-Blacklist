"""
python3 -m ru_blacklist.ptr
Resolves PTR records of every address in the given prefixes/ASNs and prints the
addresses whose reverse name matches a keyword (e.g. TSPU/DPI boxes named
"tspu-6364.no-hope.msk-m9-cr5.rascom.as20764.net").
Usage:
  python3 -m ru_blacklist.ptr config/ptr-scan.txt config/ptr-keywords.txt
"""

import argparse
import ipaddress
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor

import requests

from .asn import get_as_prefixes, normalize_asn
from .sources import iter_list_entries, read_source_lines

# Keeps a run within minutes; a /16 is 65536 lookups.
MAX_ADDRESSES = 262144


def reverse_name(address):
    try:
        return socket.gethostbyaddr(address)[0]
    except OSError:
        return None


def scan_networks(lines):
    """Turn ASN and prefix entries into networks (first word of each line)."""
    networks = []
    for entry in iter_list_entries(lines):
        token = entry.split()[0]
        asn = normalize_asn(token) if token.upper().startswith("AS") else None
        prefixes = get_as_prefixes(asn) if asn else [token]
        networks.extend(ipaddress.ip_network(prefix, strict=False) for prefix in prefixes)
    # IPv6 space is far too large to walk address by address.
    return list(ipaddress.collapse_addresses(n for n in networks if n.version == 4))


def find_matches(networks, pattern, resolve=reverse_name, workers=64):
    """Yield (address, name) for addresses whose PTR name matches ``pattern``."""
    total = sum(n.num_addresses for n in networks)
    if total > MAX_ADDRESSES:
        raise ValueError(f"{total} addresses to scan, more than {MAX_ADDRESSES}; narrow config/ptr-scan.txt")
    addresses = [str(a) for n in networks for a in n]
    with ThreadPoolExecutor(workers) as pool:
        for address, name in zip(addresses, pool.map(resolve, addresses), strict=True):
            if name and pattern.search(name):
                yield address, name


def build_parser():
    parser = argparse.ArgumentParser(description="Find addresses whose PTR record matches keywords.")
    parser.add_argument("scan", help="File with prefixes or ASNs to scan.")
    parser.add_argument("keywords", help="File with regular expressions (case-insensitive), one per line.")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        keywords = list(iter_list_entries(read_source_lines(args.keywords)))
        if not keywords:
            print(f"ERROR: no keywords in {args.keywords}", file=sys.stderr)
            return 1
        pattern = re.compile("|".join(keywords), re.IGNORECASE)
        networks = scan_networks(read_source_lines(args.scan))
        for address, name in find_matches(networks, pattern):
            print(f"# PTR: {address} {name}")
            print(f"{address}/32")
    except (requests.RequestException, OSError, ValueError, re.error) as exc:
        print(f"ERROR: PTR scan failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
