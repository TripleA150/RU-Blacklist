import argparse
import json
import sys

from .files import open_text
from .ip import convert_to_cidr

country = "RU"


def normalize_record(record):
    if not record:
        return None
    if record.get("country", "").upper() != country:
        return None

    normalized = dict(record)
    try:
        normalized["inetnum"] = convert_to_cidr(record["inetnum"])
    except ValueError as exc:
        print(f"WARNING: skipping malformed inetnum {record['inetnum']!r}: {exc}", file=sys.stderr)
        return None
    return normalized


def iter_records(lines):
    """Group the attributes we need from a ripe.db.inetnum stream into records."""
    record = {}
    for line in lines:
        if line.startswith("inetnum:"):
            if record:
                yield record
            record = {
                "inetnum": line.split("inetnum:", 1)[1].strip(),
                "descr": "",
                "netname": "",
                "country": "",
                "org": "",
            }
        elif not record:
            continue
        elif line.startswith("netname:"):
            record["netname"] = line.split("netname:", 1)[1].strip()
        elif line.startswith("descr:"):
            record["descr"] = str(record["descr"].strip() + " " + line.split("descr:", 1)[1].strip()).strip()
        elif line.startswith("mnt-by:"):
            # Maintainers are appended to netname on purpose: name filters also match e.g. VKCOMPANY-MNT.
            record["netname"] = str(record["netname"].strip() + " " + line.split("mnt-by:", 1)[1].strip()).strip()
        elif line.startswith("country:"):
            record["country"] = line.split("country:", 1)[1].strip()
        elif line.startswith("org:"):
            record["org"] = line.split("org:", 1)[1].strip()
    if record:
        yield record


def parse(filename, output_text, output_json):
    c_list = []
    with open_text(filename) as f:
        for record in iter_records(f):
            normalized = normalize_record(record)
            if normalized is not None:
                c_list.append(normalized)

    if not c_list:
        raise ValueError(f"no {country} inetnum records found in {filename}")

    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(c_list, f, indent=4)

    with open(output_text, "w", encoding="utf-8") as f:
        for item in c_list:
            for net in item["inetnum"]:
                f.write(net + " " + item["netname"] + " (" + item["org"] + ") [" + item["descr"] + "]\n")


def build_parser():
    parser = argparse.ArgumentParser(description="Parse RIPE DB for getting a list of RU networks.")
    parser.add_argument("filename", help="ripe.db.inetnum file to parse (plain or .gz).")
    parser.add_argument("output_text", help="write text db to...")
    parser.add_argument("output_json", help="write json db to...")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        parse(args.filename, args.output_text, args.output_json)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
