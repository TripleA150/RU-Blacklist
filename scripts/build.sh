#!/bin/sh
# Builds every published list in output/ from config/rules.txt and data/.
#
#   scripts/build.sh            full build (needs network: RIPEstat, RIPE whois, DNS)
#   scripts/build.sh --offline  only rebuild the nftables/ipset files from output/txt
#
# Any failure aborts the run before the published files are touched,
# so a partial list is never written.

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "${REPO_ROOT}/scripts/lib.sh"

usage() {
    sed -n '3,5s/^# \{0,1\}//p' "$0"
}

OFFLINE=0
case "${1:-}" in
    "") ;;
    --offline) OFFLINE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
esac

mkdir -p "${TXT_DIR}" "${NFT_DIR}" "${IPSET_DIR}" "${DATA_DIR}"

# ---- text lists ------------------------------------------------------------------

# match_names FILE TAG: for each line matching the "name" rules (and not the "!name"
# rules) print "# TAG: <line>" followed by the line's first field.
# Temp files instead of a pipeline, so a grep error aborts the run.
match_names() {
    [ -f "$1" ] || return 0
    _black="$(make_tmp)"
    grep_checked -iE -- "${BLACK_NAMES}" "$1" > "${_black}"
    if [ -n "${WHITE_NAMES}" ]; then
        _kept="$(make_tmp)"
        grep_checked -viE -- "${WHITE_NAMES}" "${_black}" > "${_kept}"
        _black="${_kept}"
    fi
    awk -v tag="$2" '{ print "# " tag ": " $0 "\n" $1 }' "${_black}"
}

build_text_lists() {
    black_ass_tmp="$(make_tmp)"
    with_comments_tmp="$(make_tmp)"
    netnames_tmp="$(make_tmp)"
    ptr_scan_tmp="$(make_tmp)"
    ptr_keys_tmp="$(make_tmp)"
    rules netname > "${netnames_tmp}"
    rules ptr > "${ptr_scan_tmp}"
    rules ptr-key > "${ptr_keys_tmp}"

    {
        match_names "${DATA_ALL_ASN_FILE}" "AS-Name"
        rules asn | awk '{ print "# Custom ASN: " $1 "\n" $1 }'
    } > "${black_ass_tmp}"
    {
        "${PYTHON}" -m ru_blacklist.asn "${black_ass_tmp}"
        "${PYTHON}" -m ru_blacklist.netname "${netnames_tmp}"
        if [ -s "${ptr_scan_tmp}" ] && [ -s "${ptr_keys_tmp}" ]; then
            "${PYTHON}" -m ru_blacklist.ptr "${ptr_scan_tmp}" "${ptr_keys_tmp}"
        fi
        match_names "${DATA_ALL_V4_FILE}" "NET-Name"
        match_names "${DATA_ALL_V6_FILE}" "NET-Name"
        match_names "${DATA_RIPE_V4_FILE}" "NET-Name"
        rules prefix | awk '{ print "# Custom prefix: " $1 "\n" $1 }'
    } > "${with_comments_tmp}"

    # Comments are dropped here, so consumers of blacklist.txt never re-query anything.
    aggregate_to "${BLACKLIST_FILE}" --strict "${with_comments_tmp}"
    aggregate_to "${BLACKLIST_V4_FILE}" --family 4 "${BLACKLIST_FILE}"
    aggregate_to "${BLACKLIST_V6_FILE}" --family 6 "${BLACKLIST_FILE}"
    publish_file "${black_ass_tmp}" "${DATA_BLACK_ASS_FILE}"
    publish_file "${with_comments_tmp}" "${BLACKLIST_WITH_COMMENTS_FILE}"
}

# ---- nftables ----------------------------------------------------------------------

# generate_nft INPUT OUTPUT FAMILY
generate_nft() {
    _tmp="$(make_tmp)"
    "${PYTHON}" -m ru_blacklist.nft --quiet --family "$3" "$1" "${_tmp}"
    publish_file "${_tmp}" "$2"
}

# ---- ipset -------------------------------------------------------------------------
# The files can be restored again and again, even while iptables rules use the
# set: entries are loaded into "<set>-tmp", which is then atomically swapped
# with "<set>" and destroyed.

# Fixed set parameters: "create -exist" only succeeds for an identical existing set.
IPSET_HASHSIZE=1024
IPSET_MAXELEM=65536

# generate_ipset INPUT OUTPUT SET_NAME FAMILY IPTABLES
generate_ipset() {
    count="$(count_lines "$1")"
    if [ "${count}" -gt "${IPSET_MAXELEM}" ]; then
        echo "ERROR: $1 has ${count} entries, more than maxelem ${IPSET_MAXELEM}" >&2
        return 1
    fi

    _tmp="$(make_tmp)"
    {
        cat << EOF
# IPSet blacklist configuration ($4)
# Auto-generated from $(basename "$1")
# Last updated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
# Total entries: ${count}
#
# Usage:
#   ipset restore < $(basename "$2")      # safe to repeat while rules use the set
#   $5 -I INPUT -m set --match-set $3 src -m conntrack --ctstate NEW -j DROP
#

create $3 hash:net family $4 hashsize ${IPSET_HASHSIZE} maxelem ${IPSET_MAXELEM} -exist
create $3-tmp hash:net family $4 hashsize ${IPSET_HASHSIZE} maxelem ${IPSET_MAXELEM} -exist
flush $3-tmp
EOF
        awk -v set="$3-tmp" 'NF { print "add " set " " $1 }' "$1"
        echo "swap $3-tmp $3"
        echo "destroy $3-tmp"
    } > "${_tmp}"
    publish_file "${_tmp}" "$2"
}

# ---- main --------------------------------------------------------------------------

if [ "${OFFLINE}" -eq 0 ]; then
    build_text_lists
fi
generate_nft "${BLACKLIST_FILE}" "${NFT_DIR}/blacklist.nft" both
generate_nft "${BLACKLIST_V4_FILE}" "${NFT_DIR}/blacklist-v4.nft" 4
generate_nft "${BLACKLIST_V6_FILE}" "${NFT_DIR}/blacklist-v6.nft" 6
generate_ipset "${BLACKLIST_V4_FILE}" "${IPSET_DIR}/blacklist-v4.ipset" blacklist-v4 inet iptables
generate_ipset "${BLACKLIST_V6_FILE}" "${IPSET_DIR}/blacklist-v6.ipset" blacklist-v6 inet6 ip6tables

echo "✓ Built output/: blacklist.txt $(count_lines "${BLACKLIST_FILE}") prefixes" \
    "(IPv4 $(count_lines "${BLACKLIST_V4_FILE}"), IPv6 $(count_lines "${BLACKLIST_V6_FILE}"))"
