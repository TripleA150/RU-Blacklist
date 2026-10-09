#!/bin/sh
# Builds every published list in output/.
#
#   scripts/build.sh            full build (needs network): text lists from RIPEstat
#                               and RIPE whois, then all firewall formats
#   scripts/build.sh --offline  rebuild only the VK lists and the nftables/ipset/route
#                               files from the data already in the repository
#
# The main list (output/txt/blacklist*.txt) is made of:
#   - prefixes announced by ASNs whose names match config/black-names.txt,
#   - networks registered under the netnames in config/gov-netnames.txt,
#   - data/ networks whose names match config/black-names.txt,
#   - your own ASNs and prefixes from config/custom-blacklist.txt,
# minus config/allowlist.txt. Any failure aborts the run before the published
# files are touched, so a partial list is never written.

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "${REPO_ROOT}/scripts/lib.sh"

usage() {
    sed -n '3,7s/^# \{0,1\}//p' "$0"
}

OFFLINE=0
case "${1:-}" in
    "") ;;
    --offline) OFFLINE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
esac

mkdir -p "${TXT_DIR}" "${NFT_DIR}" "${IPSET_DIR}" "${ROUTES_DIR}" "${DATA_DIR}"

# ---- text lists ------------------------------------------------------------------

# match_names FILE TAG: for each line matching the black names (and not the white
# names) print "# TAG: <line>" followed by the line's first field.
# Temp files instead of a pipeline, so an invalid pattern aborts the run.
match_names() {
    [ -f "$1" ] || return 0
    _black="$(make_tmp)"
    _kept="$(make_tmp)"
    grep_checked -iE -- "${BLACK_NAMES}" "$1" > "${_black}"
    grep_checked -viE -- "${WHITE_NAMES}" "${_black}" > "${_kept}"
    awk -v tag="$2" '{ print "# " tag ": " $0 "\n" $1 }' "${_kept}"
}

build_text_lists() {
    black_ass_tmp="$(make_tmp)"
    with_comments_tmp="$(make_tmp)"

    {
        match_names "${DATA_ALL_ASN_FILE}" "AS-Name"
        custom_asns "${CUSTOM_BLACKLIST_FILE}" | awk '{ print "# Custom ASN: " $1 "\n" $1 }'
    } > "${black_ass_tmp}"
    {
        "${PYTHON}" -m ru_blacklist.asn "${black_ass_tmp}"
        "${PYTHON}" -m ru_blacklist.netname "${GOV_NETNAMES_FILE}"
        match_names "${DATA_ALL_V4_FILE}" "NET-Name"
        match_names "${DATA_ALL_V6_FILE}" "NET-Name"
        match_names "${DATA_RIPE_V4_FILE}" "NET-Name"
        custom_prefixes "${CUSTOM_BLACKLIST_FILE}" | awk '{ print "# Custom prefix: " $1 "\n" $1 }'
    } > "${with_comments_tmp}"

    # Comments are dropped here, so consumers of blacklist.txt never re-query anything.
    aggregate_to "${BLACKLIST_FILE}" --strict "${with_comments_tmp}"
    aggregate_to "${BLACKLIST_V4_FILE}" --family 4 "${BLACKLIST_FILE}"
    aggregate_to "${BLACKLIST_V6_FILE}" --family 6 "${BLACKLIST_FILE}"
    publish_file "${black_ass_tmp}" "${DATA_BLACK_ASS_FILE}"
    publish_file "${with_comments_tmp}" "${BLACKLIST_WITH_COMMENTS_FILE}"
}

build_vk_lists() {
    _vk_raw="$(make_tmp)"
    _vk_matched="$(make_tmp)"
    _vk_exclude="$(make_tmp)"
    if [ -f "${VK_NAME_EXCLUDE_FILE}" ]; then
        read_list "${VK_NAME_EXCLUDE_FILE}" > "${_vk_exclude}"
    fi

    for source_file in "${DATA_ALL_V4_FILE}" "${DATA_ALL_V6_FILE}" "${DATA_RIPE_V4_FILE}"; do
        [ -f "${source_file}" ] || continue
        # ENVIRON instead of -v: awk -v would interpret backslash escapes in the pattern.
        # Not part of a pipeline, so an invalid pattern in config/vk-names.txt aborts the run.
        VK_NAME_PATTERN="${VK_NAME_PATTERN}" awk 'tolower($0) ~ tolower(ENVIRON["VK_NAME_PATTERN"]) { print }' \
            "${source_file}" > "${_vk_matched}"
        if [ -s "${_vk_exclude}" ]; then
            grep_checked -viF -f "${_vk_exclude}" "${_vk_matched}" | awk '{ print $1 }' >> "${_vk_raw}"
        else
            awk '{ print $1 }' "${_vk_matched}" >> "${_vk_raw}"
        fi
    done

    aggregate_to "${BLACKLIST_VK_FILE}" --strict "${_vk_raw}"
    aggregate_to "${BLACKLIST_VK_V4_FILE}" --family 4 "${BLACKLIST_VK_FILE}"
    aggregate_to "${BLACKLIST_VK_V6_FILE}" --family 6 "${BLACKLIST_VK_FILE}"
}

# ---- nftables ----------------------------------------------------------------------

# generate_nft INPUT OUTPUT FAMILY PROFILE
generate_nft() {
    _tmp="$(make_tmp)"
    "${PYTHON}" -m ru_blacklist.nft --quiet --family "$3" --profile "$4" "$1" "${_tmp}"
    publish_file "${_tmp}" "$2"
}

build_nftables() {
    generate_nft "${BLACKLIST_FILE}" "${NFT_DIR}/blacklist.nft" both vm_input
    generate_nft "${BLACKLIST_V4_FILE}" "${NFT_DIR}/blacklist-v4.nft" 4 vm_input
    generate_nft "${BLACKLIST_V6_FILE}" "${NFT_DIR}/blacklist-v6.nft" 6 vm_input
    generate_nft "${BLACKLIST_VK_FILE}" "${NFT_DIR}/blacklist-vk.nft" both vk_forward
    generate_nft "${BLACKLIST_VK_V4_FILE}" "${NFT_DIR}/blacklist-vk-v4.nft" 4 vk_forward
    generate_nft "${BLACKLIST_VK_V6_FILE}" "${NFT_DIR}/blacklist-vk-v6.nft" 6 vk_forward
}

# ---- ipset -------------------------------------------------------------------------
# The files can be restored again and again, even while iptables rules use the
# set: entries are loaded into "<set>-tmp", which is then atomically swapped
# with "<set>" and destroyed.

# Fixed set parameters: "create -exist" only succeeds for an identical existing set.
IPSET_HASHSIZE=1024
IPSET_MAXELEM=65536

# generate_ipset INPUT OUTPUT DESCRIPTION SET_NAME FAMILY
generate_ipset() {
    input_file="$1"
    output_file="$2"
    set_name="$4"
    family="$5"
    tmp_set="${set_name}-tmp"
    iptables_cmd="iptables"
    [ "${family}" = "inet6" ] && iptables_cmd="ip6tables"

    case "${set_name}" in
        blacklist-vk*)
            rule_primary="${iptables_cmd} -I OUTPUT -m set --match-set ${set_name} dst -j REJECT"
            rule_secondary="${iptables_cmd} -I FORWARD -m set --match-set ${set_name} dst -j REJECT"
            ;;
        *)
            rule_primary="${iptables_cmd} -I INPUT -m set --match-set ${set_name} src -m conntrack --ctstate NEW -j DROP"
            rule_secondary="${iptables_cmd} -I FORWARD -m set --match-set ${set_name} src -m conntrack --ctstate NEW -j DROP"
            ;;
    esac

    count="$(count_lines "${input_file}")"
    if [ "${count}" -gt "${IPSET_MAXELEM}" ]; then
        echo "ERROR: ${input_file} has ${count} entries, more than maxelem ${IPSET_MAXELEM}" >&2
        return 1
    fi

    _tmp="$(make_tmp)"
    {
        cat << EOF
# IPSet blacklist configuration $3
# Auto-generated from $(basename "${input_file}")
# Last updated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
# Total entries: ${count}
#
# Usage:
#   1. Load or refresh the set (safe to repeat while rules use it):
#      ipset restore < $(basename "${output_file}")
#
#   2. Use with iptables/ip6tables:
#      ${rule_primary}
#      ${rule_secondary}
#
#   3. To flush/delete the set:
#      ipset flush ${set_name}
#      ipset destroy ${set_name}
#

create ${set_name} hash:net family ${family} hashsize ${IPSET_HASHSIZE} maxelem ${IPSET_MAXELEM} -exist
create ${tmp_set} hash:net family ${family} hashsize ${IPSET_HASHSIZE} maxelem ${IPSET_MAXELEM} -exist
flush ${tmp_set}
EOF
        awk -v set="${tmp_set}" 'NF { print "add " set " " $1 }' "${input_file}"
        echo "swap ${tmp_set} ${set_name}"
        echo "destroy ${tmp_set}"
    } > "${_tmp}"
    publish_file "${_tmp}" "${output_file}"
}

build_ipset() {
    generate_ipset "${BLACKLIST_V4_FILE}" "${IPSET_DIR}/blacklist-v4.ipset" "(IPv4 only)" "blacklist-v4" "inet"
    generate_ipset "${BLACKLIST_V6_FILE}" "${IPSET_DIR}/blacklist-v6.ipset" "(IPv6 only)" "blacklist-v6" "inet6"
    generate_ipset "${BLACKLIST_VK_V4_FILE}" "${IPSET_DIR}/blacklist-vk-v4.ipset" "(VK names, IPv4 only)" "blacklist-vk-v4" "inet"
    generate_ipset "${BLACKLIST_VK_V6_FILE}" "${IPSET_DIR}/blacklist-vk-v6.ipset" "(VK names, IPv6 only)" "blacklist-vk-v6" "inet6"
}

# ---- Linux routes (VK networks to the loopback interface) --------------------------

# generate_routes INPUT OUTPUT TITLE ROUTE_FORMAT
generate_routes() {
    _tmp="$(make_tmp)"
    {
        cat << EOF
# Linux routes for VK networks ($3)
# Auto-generated by scripts/build.sh
# Last updated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
#
# Apply:
#   sudo sh $(basename "$2")
#

EOF
        awk -v fmt="$4" 'NF { printf fmt, $1 }' "$1"
    } > "${_tmp}"
    publish_file "${_tmp}" "$2"
}

build_routes() {
    generate_routes "${BLACKLIST_VK_V4_FILE}" "${ROUTES_DIR}/blacklist-vk-v4.routes" "IPv4" 'ip route replace %s via 127.0.0.1 dev lo onlink\n'
    generate_routes "${BLACKLIST_VK_V6_FILE}" "${ROUTES_DIR}/blacklist-vk-v6.routes" "IPv6" 'ip -6 route replace %s via ::1 dev lo\n'
}

# ---- main --------------------------------------------------------------------------

if [ "${OFFLINE}" -eq 0 ]; then
    build_text_lists
fi
build_vk_lists
build_nftables
build_ipset
build_routes

echo "✓ Built output/:"
echo "  blacklist.txt: $(count_lines "${BLACKLIST_FILE}") prefixes (IPv4 $(count_lines "${BLACKLIST_V4_FILE}"), IPv6 $(count_lines "${BLACKLIST_V6_FILE}"))"
echo "  blacklist-vk.txt: $(count_lines "${BLACKLIST_VK_FILE}") prefixes"
