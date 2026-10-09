#!/bin/sh
# Refreshes data/ from RIPE (needs network):
#   - all Russian ASNs and prefixes (RIPEstat country resource list),
#   - their AS/network/organisation names, resolved offline from RIPE DB dumps,
#   - all RU inetnum objects (data/ripe-ru-ipv4.txt and .json).
#
#   scripts/refresh-ripe-data.sh [DUMP_DIR]
#
# DUMP_DIR keeps the downloaded dumps for reuse; by default they go to a
# temporary directory that is removed afterwards. Run scripts/build.sh next.

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "${REPO_ROOT}/scripts/lib.sh"

RIPE_SPLIT_URL="${RIPE_SPLIT_URL:-https://ftp.ripe.net/ripe/dbase/split}"
DUMP_DIR="${1:-${WORK_DIR}/ripe}"
mkdir -p "${DUMP_DIR}" "${DATA_DIR}"

for name in inetnum inet6num aut-num organisation; do
    echo "Downloading ripe.db.${name}.gz..."
    curl -fsSL --retry 5 --retry-delay 30 -o "${DUMP_DIR}/ripe.db.${name}.gz" "${RIPE_SPLIT_URL}/ripe.db.${name}.gz"
done

"${PYTHON}" -m ru_blacklist.country --output-dir "${DATA_DIR}"
"${PYTHON}" -m ru_blacklist.describe --ripe-dump-dir "${DUMP_DIR}" --refresh --limit 300 \
    "${DATA_ALL_ASN_FILE}" "${DATA_ALL_V4_FILE}" "${DATA_ALL_V6_FILE}"

ripe_txt_tmp="$(make_tmp)"
ripe_json_tmp="$(make_tmp)"
"${PYTHON}" -m ru_blacklist.inetnum "${DUMP_DIR}/ripe.db.inetnum.gz" "${ripe_txt_tmp}" "${ripe_json_tmp}"

# check FILE MIN_LINES: refuse data that is clearly incomplete.
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"
{ echo "| file | lines |"; echo "|---|---:|"; } >> "${summary}"
check() {
    lines="$(count_lines "$1")"
    echo "| $(basename "$2") | ${lines} |" >> "${summary}"
    echo "$(basename "$2"): ${lines} lines"
    if [ "${lines}" -lt "$3" ]; then
        echo "ERROR: $(basename "$2") has only ${lines} lines, expected at least $3" >&2
        exit 1
    fi
}
check "${DATA_ALL_ASN_FILE}" "${DATA_ALL_ASN_FILE}" 4000
check "${DATA_ALL_V4_FILE}" "${DATA_ALL_V4_FILE}" 8000
check "${DATA_ALL_V6_FILE}" "${DATA_ALL_V6_FILE}" 1500
check "${ripe_txt_tmp}" "${DATA_RIPE_V4_FILE}" 130000

publish_file "${ripe_txt_tmp}" "${DATA_RIPE_V4_FILE}"
publish_file "${ripe_json_tmp}" "${DATA_RIPE_V4_JSON_FILE}"

unresolved="$(cat "${DATA_ALL_ASN_FILE}" "${DATA_ALL_V4_FILE}" "${DATA_ALL_V6_FILE}" | grep -c -- '-no-description-' || true)"
echo "Entries without a description: ${unresolved}" | tee -a "${summary}"
