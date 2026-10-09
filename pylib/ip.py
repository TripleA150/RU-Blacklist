import ipaddress


def parse_range(ip_range):
    """Parse 'start - end' (IPv4/IPv6) or a CIDR prefix into a pair of ip_address objects."""
    text = ip_range.strip()
    if "-" in text:
        start, end = (part.strip() for part in text.split("-", 1))
        start_ip = ipaddress.ip_address(start)
        end_ip = ipaddress.ip_address(end)
        if start_ip.version != end_ip.version:
            raise ValueError(f"Mixed address families in range: {ip_range!r}")
        if start_ip > end_ip:
            raise ValueError(f"Range start is greater than end: {ip_range!r}")
        return start_ip, end_ip
    network = ipaddress.ip_network(text, strict=False)
    return network.network_address, network.broadcast_address


def convert_to_cidr(ip_range):
    """Convert 'start - end' range or a CIDR prefix into a list of CIDR strings."""
    start_ip, end_ip = parse_range(ip_range)
    return [str(cidr) for cidr in ipaddress.summarize_address_range(start_ip, end_ip)]


def network_sort_key(network):
    """Numeric sort key: IPv4 before IPv6, then by address and prefix length."""
    return network.version, int(network.network_address), network.prefixlen


def sort_prefixes(prefixes):
    """Sort prefix strings numerically; unparsable entries keep their order at the end."""
    parsed, invalid = [], []
    for prefix in prefixes:
        try:
            parsed.append((network_sort_key(ipaddress.ip_network(prefix, strict=False)), prefix))
        except ValueError:
            invalid.append(prefix)
    return [prefix for _, prefix in sorted(parsed)] + invalid
