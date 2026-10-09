#!/usr/bin/env python3
"""
check_nft_blacklist.py
Checks if an IP address is in the nftables blacklist configuration.
Usage:
  check_nft_blacklist.py nft_bl.conf 192.168.1.1
  check_nft_blacklist.py nft_bl.conf 2001:db8::1
"""

import re
import sys
from ipaddress import ip_address, ip_network
from pathlib import Path


def iter_set_blocks(content):
    current_name = None
    current_lines = []
    brace_depth = 0

    for line in content.splitlines():
        if current_name is None:
            match = re.match(r"\s*set\s+([A-Za-z0-9_]+)\s*\{", line)
            if match:
                current_name = match.group(1)
                current_lines = [line]
                brace_depth = line.count("{") - line.count("}")
            continue

        current_lines.append(line)
        brace_depth += line.count("{") - line.count("}")
        if brace_depth == 0:
            yield current_name, "\n".join(current_lines)
            current_name = None
            current_lines = []


ELEMENTS_RE = re.compile(r"elements\s*=\s*\{(.*?)\}", re.DOTALL)
SET_TYPE_RE = re.compile(r"\btype\s+(ipv4_addr|ipv6_addr)\b")


def parse_nft_config(config_path):
    """Extract IPv4 and IPv6 prefixes from nftables config."""
    p = Path(config_path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    content = p.read_text(encoding="utf-8")
    prefixes = {"ipv4_addr": [], "ipv6_addr": []}

    for _, block in iter_set_blocks(content):
        set_type = SET_TYPE_RE.search(block)
        if not set_type:
            continue
        for elements in ELEMENTS_RE.findall(block):
            for item in elements.replace("\n", ",").split(","):
                item = item.split("#", 1)[0].strip()
                if not item:
                    continue
                try:
                    prefixes[set_type.group(1)].append(ip_network(item, strict=False))
                except ValueError as e:
                    print(f"Warning: Could not parse prefix '{item}': {e}", file=sys.stderr)

    return prefixes["ipv4_addr"], prefixes["ipv6_addr"]


def check_ip_in_blacklist(ip_addr, v4_prefixes, v6_prefixes):
    """Check if IP address is in any of the blacklist prefixes."""
    try:
        addr = ip_address(ip_addr)
    except ValueError as e:
        raise ValueError(f"Invalid IP address: {ip_addr} ({e})") from e

    prefixes = v4_prefixes if addr.version == 4 else v6_prefixes

    for prefix in prefixes:
        if addr in prefix:
            return True, prefix

    return False, None


def main(argv):
    if len(argv) < 3:
        print("Usage: python3 check_nft_blacklist.py <nft_config.conf> <ip_address>")
        print("Examples:")
        print("  check_nft_blacklist.py nft_bl.conf 192.168.1.1")
        print("  check_nft_blacklist.py nft_bl.conf 2001:db8::1")
        return 2

    config_file = argv[1]
    ip_to_check = argv[2]

    # Parse the nftables config
    try:
        print(f"Loading blacklist from: {config_file}")
        v4_prefixes, v6_prefixes = parse_nft_config(config_file)
        print(f"Loaded {len(v4_prefixes)} IPv4 prefixes and {len(v6_prefixes)} IPv6 prefixes")
    except (OSError, ValueError) as e:
        print(f"ERROR: Could not parse config file: {e}", file=sys.stderr)
        return 3

    # Check if IP is in blacklist
    try:
        is_blocked, matching_prefix = check_ip_in_blacklist(ip_to_check, v4_prefixes, v6_prefixes)

        print(f"\nChecking IP: {ip_to_check}")
        print("-" * 50)

        if is_blocked:
            print("✗ BLOCKED - IP is in blacklist")
            print(f"  Matching prefix: {matching_prefix}")
            return 1
        else:
            print("✓ OK - IP is NOT in blacklist")
            return 0

    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main(sys.argv))
