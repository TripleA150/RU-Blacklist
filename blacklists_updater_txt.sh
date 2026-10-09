#!/bin/sh
# Builds the plain-text blacklists (blacklists/*.txt) from:
#   - prefixes announced by ASNs whose names match lists/black-names.txt,
#   - networks registered under the netnames in lists/ru-gov-netnames.txt,
#   - auto/ networks whose names match lists/black-names.txt,
#   - your own ASNs and prefixes from lists/custom-blacklist.txt.
# Needs network access (RIPEstat API and RIPE whois). Any failure aborts the
# run before the published files are touched, so a partial list is never written.

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "${SCRIPT_DIR}/blacklists_updater_common.subr"

ensure_blacklist_base_dirs

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

black_ass_tmp="$(make_tmp)"
with_comments_tmp="$(make_tmp)"

{
    match_names "${AUTO_ALL_ASN_FILE}" "AS-Name"
    custom_asns "${CUSTOM_BLACKLIST_FILE}" | awk '{ print "# Custom ASN: " $1 "\n" $1 }'
} > "${black_ass_tmp}"
{
    "${PYTHON}" "${NETWORK_LIST_FROM_AS}" "${black_ass_tmp}"
    "${PYTHON}" "${NETWORK_LIST_FROM_NETNAME}" "${RU_GOV_NETNAMES_FILE}"
    match_names "${AUTO_ALL_V4_FILE}" "NET-Name"
    match_names "${AUTO_ALL_V6_FILE}" "NET-Name"
    match_names "${AUTO_RIPE_V4_FILE}" "NET-Name"
    custom_prefixes "${CUSTOM_BLACKLIST_FILE}" | awk '{ print "# Custom prefix: " $1 "\n" $1 }'
} > "${with_comments_tmp}"

# Comments are dropped here, so consumers of blacklist.txt never re-query anything.
aggregate_to "${BLACKLIST_FILE}" --strict "${with_comments_tmp}"
aggregate_to "${BLACKLIST_V4_FILE}" --family 4 "${BLACKLIST_FILE}"
aggregate_to "${BLACKLIST_V6_FILE}" --family 6 "${BLACKLIST_FILE}"
publish_file "${black_ass_tmp}" "${AUTO_BLACK_ASS_FILE}"
publish_file "${with_comments_tmp}" "${BLACKLIST_WITH_COMMENTS_FILE}"

build_vk_name_blacklists

echo "✓ Generated blacklist files"
echo "  Mixed (IPv4/IPv6): ${BLACKLIST_FILE} ($(count_lines "${BLACKLIST_FILE}") entries)"
echo "  IPv4 only: ${BLACKLIST_V4_FILE} ($(count_lines "${BLACKLIST_V4_FILE}") entries)"
echo "  IPv6 only: ${BLACKLIST_V6_FILE} ($(count_lines "${BLACKLIST_V6_FILE}") entries)"
echo "  VK only: ${BLACKLIST_VK_FILE} ($(count_lines "${BLACKLIST_VK_FILE}") entries)"
