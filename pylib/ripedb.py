"""Offline lookups in RIPE database split dumps.

The dumps (https://ftp.ripe.net/ripe/dbase/split/) contain every object of one
class and are refreshed daily. Resolving names from them replaces thousands of
whois queries, which RIPE rate-limits, with a few bulk downloads.
"""

import bisect

from .files import open_text
from .ip import parse_range

DUMP_FILES = {
    "aut-num": "ripe.db.aut-num.gz",
    "inetnum": "ripe.db.inetnum.gz",
    "inet6num": "ripe.db.inet6num.gz",
    "organisation": "ripe.db.organisation.gz",
}


def iter_objects(path, attributes):
    """Stream RPSL objects as dicts.

    Each dict has "_class" and "_key" (the first attribute name and value) plus
    the first value of every attribute listed in ``attributes``.
    """
    obj = {}
    with open_text(path) as dump:
        for line in dump:
            if not line.strip():
                if obj:
                    yield obj
                    obj = {}
                continue
            first = line[0]
            if first in "%#" or first in " \t+":
                # Comments and continuation lines are not needed for names/handles.
                continue
            name, sep, value = line.partition(":")
            if not sep:
                continue
            name = name.strip().lower()
            if not obj:
                obj["_class"] = name
                obj["_key"] = value.strip()
            elif name in attributes and name not in obj:
                obj[name] = value.strip()
    if obj:
        yield obj


def load_org_names(path):
    """Map organisation handles (ORG-XXX-RIPE) to org-name."""
    return {
        obj["_key"].upper(): obj["org-name"]
        for obj in iter_objects(path, {"org-name"})
        if obj["_class"] == "organisation" and "org-name" in obj
    }


def load_aut_nums(path, wanted=None):
    """Map "AS123" to (as-name, org handle or None), optionally only for ``wanted`` ASNs."""
    result = {}
    for obj in iter_objects(path, {"as-name", "org"}):
        if obj["_class"] != "aut-num":
            continue
        asn = obj["_key"].upper()
        if wanted is None or asn in wanted:
            result[asn] = (obj.get("as-name"), obj.get("org"))
    return result


def resolve_networks(path, object_class, targets):
    """Find, for every target prefix, the most specific object covering it (like a whois lookup).

    Returns {target: (netname, org handle or None)} for the targets that were found.
    """
    parsed = []
    for target in targets:
        try:
            start, end = parse_range(target)
        except ValueError:
            continue
        parsed.append((int(start), int(end), target))
    parsed.sort()
    starts = [start for start, _, _ in parsed]

    best = {}
    for obj in iter_objects(path, {"netname", "org"}):
        if obj["_class"] != object_class:
            continue
        try:
            start_ip, end_ip = parse_range(obj["_key"])
        except ValueError:
            continue
        start, end = int(start_ip), int(end_ip)
        size = end - start
        for idx in range(bisect.bisect_left(starts, start), bisect.bisect_right(starts, end)):
            _, target_end, target = parsed[idx]
            if target_end <= end:
                current = best.get(target)
                if current is None or size < current[0]:
                    best[target] = (size, obj.get("netname"), obj.get("org"))
    return {target: (netname, org) for target, (_, netname, org) in best.items()}
