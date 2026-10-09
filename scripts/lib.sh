#!/bin/sh
# shellcheck shell=sh disable=SC2034  # variables are used by the sourcing scripts

# Paths and helpers shared by the scripts in scripts/.
# The sourcing script must set REPO_ROOT and enable "set -eu" first.

: "${REPO_ROOT:?REPO_ROOT must be set before sourcing scripts/lib.sh}"

PYTHON="${PYTHON:-python3}"
# Run the ru_blacklist package straight from this checkout.
export PYTHONPATH="${REPO_ROOT}${PYTHONPATH:+:${PYTHONPATH}}"

CONFIG_DIR="${REPO_ROOT}/config"
DATA_DIR="${REPO_ROOT}/data"
OUTPUT_DIR="${REPO_ROOT}/output"
TXT_DIR="${OUTPUT_DIR}/txt"
NFT_DIR="${OUTPUT_DIR}/nftables"
IPSET_DIR="${OUTPUT_DIR}/ipset"
ROUTES_DIR="${OUTPUT_DIR}/routes"

# Hand-edited configuration
GOV_NETNAMES_FILE="${CONFIG_DIR}/gov-netnames.txt"
CUSTOM_BLACKLIST_FILE="${CONFIG_DIR}/custom-blacklist.txt"
ALLOWLIST_FILE="${CONFIG_DIR}/allowlist.txt"
VK_NAME_EXCLUDE_FILE="${CONFIG_DIR}/vk-exclude.txt"

# RIPE data refreshed by scripts/refresh-ripe-data.sh
DATA_ALL_ASN_FILE="${DATA_DIR}/all-ru-asn.txt"
DATA_ALL_V4_FILE="${DATA_DIR}/all-ru-ipv4.txt"
DATA_ALL_V6_FILE="${DATA_DIR}/all-ru-ipv6.txt"
DATA_RIPE_V4_FILE="${DATA_DIR}/ripe-ru-ipv4.txt"
DATA_RIPE_V4_JSON_FILE="${DATA_DIR}/ripe-ru-ipv4.json"
DATA_BLACK_ASS_FILE="${DATA_DIR}/black_ass.txt"

# Published text lists
BLACKLIST_FILE="${TXT_DIR}/blacklist.txt"
BLACKLIST_WITH_COMMENTS_FILE="${TXT_DIR}/blacklist_with_comments.txt"
BLACKLIST_V4_FILE="${TXT_DIR}/blacklist-v4.txt"
BLACKLIST_V6_FILE="${TXT_DIR}/blacklist-v6.txt"
BLACKLIST_VK_FILE="${TXT_DIR}/blacklist-vk.txt"
BLACKLIST_VK_V4_FILE="${TXT_DIR}/blacklist-vk-v4.txt"
BLACKLIST_VK_V6_FILE="${TXT_DIR}/blacklist-vk-v6.txt"

# Header lines that change on every run; ignored when deciding whether a file changed.
TIMESTAMP_LINE_RE='^# (Last updated|Generated):'

# Print the non-comment, non-empty lines of a file.
read_list() {
    sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e '/^#/d' -e '/^$/d' "$1"
}

# Print the patterns of a file joined with "|"; fails if the file has none,
# because an empty pattern would match every line.
read_patterns() {
    _patterns="$(read_list "$1" | paste -s -d '|' -)"
    if [ -z "${_patterns}" ]; then
        echo "ERROR: no patterns in $1" >&2
        return 1
    fi
    printf '%s\n' "${_patterns}"
}

BLACK_NAMES="$(read_patterns "${CONFIG_DIR}/black-names.txt")"
WHITE_NAMES="$(read_patterns "${CONFIG_DIR}/white-names.txt")"
VK_NAME_PATTERN="$(read_patterns "${CONFIG_DIR}/vk-names.txt")"

# Fail before anything is touched if a pattern does not compile; otherwise grep/awk
# would just match nothing and the lists would silently shrink.
for _pattern_file in black-names.txt white-names.txt; do
    _rc=0
    grep -E -- "$(read_patterns "${CONFIG_DIR}/${_pattern_file}")" < /dev/null > /dev/null || _rc=$?
    if [ "${_rc}" -gt 1 ]; then
        echo "ERROR: invalid regular expression in config/${_pattern_file}" >&2
        exit 1
    fi
done
if ! VK_NAME_PATTERN="${VK_NAME_PATTERN}" awk 'BEGIN { if ("" ~ ENVIRON["VK_NAME_PATTERN"]) {} }'; then
    echo "ERROR: invalid regular expression in config/vk-names.txt" >&2
    exit 1
fi

# Scratch space inside the repo, so publishing with mv is an atomic rename.
WORK_DIR="$(mktemp -d "${REPO_ROOT}/.build.XXXXXX")"
trap 'rm -rf "${WORK_DIR}"' EXIT
trap 'exit 130' INT TERM

# Print a fresh temp file path inside WORK_DIR.
make_tmp() {
    mktemp "${WORK_DIR}/tmp.XXXXXX"
}

# Move $1 over $2, unless the two differ only in timestamp header lines
# (then $2 is left untouched and no needless commit happens).
publish_file() {
    if [ -f "$2" ] && \
       [ "$(grep -vE "${TIMESTAMP_LINE_RE}" "$1" | cksum)" = "$(grep -vE "${TIMESTAMP_LINE_RE}" "$2" | cksum)" ]; then
        rm -f "$1"
        return 0
    fi
    chmod 644 "$1"
    mv -f "$1" "$2"
}

# aggregate_to OUTPUT [ru_blacklist.aggregate args...]
# Validates, collapses and allowlist-filters prefixes, then publishes OUTPUT.
aggregate_to() {
    _output="$1"
    shift
    _tmp="$(make_tmp)"
    if [ -f "${ALLOWLIST_FILE}" ]; then
        set -- --exclude "${ALLOWLIST_FILE}" "$@"
    fi
    "${PYTHON}" -m ru_blacklist.aggregate -o "${_tmp}" "$@"
    publish_file "${_tmp}" "${_output}"
}

# grep_checked ARGS...: like grep, but "no match" (exit 1) is not an error,
# while a broken pattern (exit 2) aborts instead of silently matching nothing.
grep_checked() {
    _rc=0
    grep "$@" || _rc=$?
    if [ "${_rc}" -gt 1 ]; then
        echo "ERROR: grep failed (invalid pattern in config/?): grep $*" >&2
        return "${_rc}"
    fi
}

# custom_asns FILE / custom_prefixes FILE: the ASN ("AS123") or the prefix entries
# of a custom list. Only the first word of a line counts, so "1.2.3.0/24 # why" works.
custom_asns() {
    [ -f "$1" ] || return 0
    read_list "$1" | awk '{ print toupper($1) }' | grep_checked -E '^AS[0-9]+$'
}

custom_prefixes() {
    [ -f "$1" ] || return 0
    read_list "$1" | awk '{ print $1 }' | grep_checked -viE '^AS[0-9]+$'
}

# Print the number of non-empty lines in a file.
count_lines() {
    grep -c . "$1" || true
}
