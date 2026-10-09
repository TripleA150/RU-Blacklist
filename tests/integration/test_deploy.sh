#!/bin/sh
# shellcheck disable=SC2016,SC2329  # sh -c snippets are single-quoted on purpose; helpers are called via check/check_rc
# End-to-end test of deploy/ru-blacklist-update.sh with both backends.
# Needs root, nft, ipset and iptables; runs inside a throw-away network namespace,
# so the host firewall is never touched. Usage: sudo tests/integration/test_deploy.sh

set -eu

if [ -z "${IN_NETNS:-}" ]; then
    [ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 2; }
    IN_NETNS=1 exec unshare -n "$0" "$@"
fi

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
UPDATE="${REPO_ROOT}/deploy/ru-blacklist-update.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT
LISTS="${TMP}/lists"
STATE="${TMP}/state"
CONF="${TMP}/ru-blacklist.conf"
mkdir -p "${LISTS}"
for f in blacklist-v4.txt blacklist-v6.txt blacklist-vk-v4.txt blacklist-vk-v6.txt; do
    cp "${REPO_ROOT}/output/txt/${f}" "${LISTS}/${f}"
done

FAILED=0
pass() { echo "ok   - $1"; }
fail() { echo "FAIL - $1"; FAILED=1; }
check() {  # DESCRIPTION COMMAND...
    desc="$1"; shift
    if "$@" > /dev/null 2>&1; then pass "${desc}"; else fail "${desc}"; fi
}
check_rc() {  # DESCRIPTION EXPECTED_RC COMMAND...
    desc="$1"; expected="$2"; shift 2
    rc=0; "$@" > "${TMP}/out" 2>&1 || rc=$?
    if [ "${rc}" -eq "${expected}" ]; then pass "${desc}"; else fail "${desc} (rc=${rc}, expected ${expected})"; cat "${TMP}/out"; fi
}
write_conf() {
    cat > "${CONF}" << EOF
BASE_URL="file://${LISTS}"
STATE_DIR="${STATE}"
BACKEND="$1"
BLOCK_GOV_INPUT="yes"
BLOCK_VK_FORWARD="yes"
BLOCK_VK_OUTPUT="${2:-no}"
VPN_IFACES="${3:-}"
ALLOW_PREFIXES="${4:-}"
EOF
}
run() { "${UPDATE}" --config "${CONF}" "$@"; }
nft_table() { nft list table inet ru_blacklist; }
table_has() { nft_table | grep -q -- "$1"; }

echo "# nftables backend"
write_conf nftables no "wg0 awg0" "198.51.100.7 2001:db8::/48"
check_rc "first apply" 0 run
check "gov_v4 set filled" table_has "elements = {"
check "input chain drops gov sources" table_has "ip saddr @gov_v4 counter"
check "forward chain limited to VPN interfaces" table_has 'iifname { "wg0", "awg0" } ip daddr @vk_v4'
check "allowlist rule present" table_has "ip saddr 198.51.100.7 return"
check "no output chain by default" sh -c '! nft list table inet ru_blacklist | grep -q "hook output"'
check_rc "second apply is idempotent" 0 run
check "state cached" test -s "${STATE}/blacklist-v4.txt"

write_conf nftables yes
check_rc "apply with BLOCK_VK_OUTPUT" 0 run
check "output chain present" table_has "hook output"
check "forward chain covers all traffic without VPN_IFACES" sh -c '! nft list table inet ru_blacklist | grep -q iifname'

nft_table > "${TMP}/before"
head -n 10 "${REPO_ROOT}/output/txt/blacklist-v4.txt" > "${LISTS}/blacklist-v4.txt"
check_rc "tiny list is refused" 3 run
nft_table > "${TMP}/after"
check "rules untouched after refusal" cmp -s "${TMP}/before" "${TMP}/after"
check_rc "--force applies a refused list" 0 run --force
cp "${REPO_ROOT}/output/txt/blacklist-v4.txt" "${LISTS}/blacklist-v4.txt"
check_rc "full list applies again" 0 run --force

printf '<html>rate limited</html>\n' > "${LISTS}/blacklist-v4.txt"
check_rc "invalid download falls back to cache" 0 run
check "cache kept the full list" sh -c "[ \$(grep -c . '${STATE}/blacklist-v4.txt') -gt 300 ]"
cp "${REPO_ROOT}/output/txt/blacklist-v4.txt" "${LISTS}/blacklist-v4.txt"

sed -i "s#^BASE_URL=.*#BASE_URL=\"file://${TMP}/missing\"#" "${CONF}"
check_rc "unreachable source falls back to cache" 0 run
check_rc "dry run works" 0 run --dry-run
check_rc "remove" 0 run --remove
check "table removed" sh -c '! nft list table inet ru_blacklist'

echo "# ipset backend"
rm -rf "${STATE}"
write_conf ipset no "wg0" "198.51.100.7"
check_rc "first apply" 0 run
check "gov set filled" sh -c '[ $(ipset list ru-bl-gov-v4 | grep -c "/") -gt 300 ]'
check "vk v6 set exists" ipset list -n ru-bl-vk-v6
check "INPUT jumps to our chain" iptables -C INPUT -j RU_BL_INPUT
check "FORWARD jump in ip6tables" ip6tables -C FORWARD -j RU_BL_FORWARD
check "forward rule limited to wg0" sh -c 'iptables -S RU_BL_FORWARD | grep -q -- "-i wg0"'
check "allowlist rule present" sh -c 'iptables -S RU_BL_INPUT | grep -q "198.51.100.7/32 -j RETURN"'
check_rc "second apply is idempotent" 0 run
check "exactly one jump after re-apply" sh -c '[ $(iptables -S INPUT | grep -c RU_BL_INPUT) -eq 1 ]'
check "no leftover tmp sets" sh -c '! ipset list -n | grep -q -- "-tmp"'
check_rc "remove" 0 run --remove
check "sets removed" sh -c '! ipset list -n | grep -q ru-bl'
check "chains removed" sh -c '! iptables -n -L RU_BL_INPUT'

echo "# published ipset/nft files load repeatedly"
for f in "${REPO_ROOT}"/output/nftables/*.nft; do
    check "$(basename "${f}") loads twice" sh -c "nft -f '${f}' && nft -f '${f}'"
done
for f in "${REPO_ROOT}"/output/ipset/*.ipset; do
    check "$(basename "${f}") restores twice" sh -c "ipset restore < '${f}' && ipset restore < '${f}'"
done

exit "${FAILED}"
