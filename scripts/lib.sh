#!/bin/sh
# shellcheck shell=sh disable=SC2034  # variables are used by the sourcing scripts

# Paths and helpers shared by the scripts in scripts/.
# The sourcing script must set REPO_ROOT and enable "set -eu" first.

: "${REPO_ROOT:?REPO_ROOT must be set before sourcing scripts/lib.sh}"

PYTHON="${PYTHON:-python3}"
# Run the ru_blacklist package straight from this checkout.
export PYTHONPATH="${REPO_ROOT}${PYTHONPATH:+:${PYTHONPATH}}"

RULES_FILE="${REPO_ROOT}/config/rules.txt"
DATA_DIR="${REPO_ROOT}/data"
TXT_DIR="${REPO_ROOT}/output/txt"
NFT_DIR="${REPO_ROOT}/output/nftables"
IPSET_DIR="${REPO_ROOT}/output/ipset"

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

# Header lines that change on every run; ignored when deciding whether a file changed.
TIMESTAMP_LINE_RE='^# (Last updated|Generated):'

# rules KIND: print the values of one kind of rule from config/rules.txt (see its header).
rules() {
    "${PYTHON}" -m ru_blacklist.rules "${RULES_FILE}" "$1"
}

# Run once up front: a broken rules file aborts before anything is touched.
BLACK_NAMES="$(rules name)"  # not in a pipeline, so "set -e" stops on a bad rules file
BLACK_NAMES="$(printf '%s\n' "${BLACK_NAMES}" | paste -s -d '|' -)"
WHITE_NAMES="$(rules '!name' | paste -s -d '|' -)"
if [ -z "${BLACK_NAMES}" ]; then
    echo "ERROR: no 'name' rules in config/rules.txt" >&2
    exit 1
fi
# grep/awk would otherwise just match nothing on a broken pattern and the list would shrink.
for _pattern in "${BLACK_NAMES}" "${WHITE_NAMES:-x}"; do
    _rc=0
    grep -E -- "${_pattern}" < /dev/null > /dev/null || _rc=$?
    if [ "${_rc}" -gt 1 ]; then
        echo "ERROR: invalid 'name' regular expression in config/rules.txt" >&2
        exit 1
    fi
done

# Scratch space inside the repo, so publishing with mv is an atomic rename.
WORK_DIR="$(mktemp -d "${REPO_ROOT}/.build.XXXXXX")"
trap 'rm -rf "${WORK_DIR}"' EXIT
trap 'exit 130' INT TERM

# Print a fresh temp file path inside WORK_DIR.
make_tmp() {
    mktemp "${WORK_DIR}/tmp.XXXXXX"
}

ALLOWLIST_FILE="$(make_tmp)"
rules allow > "${ALLOWLIST_FILE}"

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
    "${PYTHON}" -m ru_blacklist.aggregate --exclude "${ALLOWLIST_FILE}" -o "${_tmp}" "$@"
    publish_file "${_tmp}" "${_output}"
}

# grep_checked ARGS...: like grep, but "no match" (exit 1) is not an error.
grep_checked() {
    _rc=0
    grep "$@" || _rc=$?
    if [ "${_rc}" -gt 1 ]; then
        return "${_rc}"
    fi
}

# Print the number of non-empty lines in a file.
count_lines() {
    grep -c . "$1" || true
}
