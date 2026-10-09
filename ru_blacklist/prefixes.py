"""Parsing, aggregation and set arithmetic for IP prefix lists."""

import ipaddress


def parse_prefix_lines(lines):
    """Parse the first token of every non-comment line as a prefix.

    Returns (networks, invalid) where invalid is a list of (line number, token).
    Lines such as "10.0.0.0/8 SOME-NETNAME (Org)" are accepted as well.
    """
    networks, invalid = [], []
    for lineno, line in enumerate(lines, start=1):
        tokens = line.split("#", 1)[0].split()
        if not tokens:
            continue
        try:
            networks.append(ipaddress.ip_network(tokens[0], strict=False))
        except ValueError:
            invalid.append((lineno, tokens[0]))
    return networks, invalid


def intervals(networks, version):
    """Merge networks of one IP version into sorted, non-overlapping [start, end] integer intervals."""
    spans = sorted((int(n.network_address), int(n.broadcast_address)) for n in networks if n.version == version)
    merged = []
    for start, end in spans:
        if merged and start <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return merged


def subtract_intervals(left, right):
    """Return the parts of ``left`` not covered by ``right`` (both merged and sorted)."""
    result = []
    j = 0
    for start, end in left:
        while j < len(right) and right[j][1] < start:
            j += 1
        cursor = start
        k = j
        while k < len(right) and right[k][0] <= end and cursor <= end:
            if right[k][0] > cursor:
                result.append([cursor, right[k][0] - 1])
            cursor = max(cursor, right[k][1] + 1)
            k += 1
        if cursor <= end:
            result.append([cursor, end])
    return result


def interval_size(spans):
    return sum(end - start + 1 for start, end in spans)


def intervals_to_networks(spans, version):
    address = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    networks = []
    for start, end in spans:
        networks.extend(ipaddress.summarize_address_range(address(start), address(end)))
    return networks


def aggregate(networks, exclude=()):
    """Collapse networks into the minimal sorted CIDR list (IPv4 first), minus ``exclude``."""
    result = []
    for version in (4, 6):
        spans = intervals(networks, version)
        if exclude:
            spans = subtract_intervals(spans, intervals(exclude, version))
        result.extend(intervals_to_networks(spans, version))
    return result
