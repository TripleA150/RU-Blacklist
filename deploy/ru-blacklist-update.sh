#!/bin/sh
# ru-blacklist-update: downloads the RU-Blacklist lists and applies them to the
# local firewall (nftables, or ipset + iptables). Meant to run from a systemd
# timer; every run rebuilds the rules atomically, so it is safe to repeat and
# also restores the rules after a reboot.
#
# Safety:
#   - a list that fails to download is taken from the cache of the last good run;
#   - lists that look broken (invalid lines, too few entries, sudden shrink)
#     are refused and the current firewall state is left untouched;
#   - rules live in their own nftables table / iptables chains and never touch
#     the rest of your firewall.
#
# Usage: ru-blacklist-update [--config FILE] [--dry-run] [--force] [--remove]

set -eu

PROG="ru-blacklist-update"
CONFIG_FILE="/etc/ru-blacklist.conf"
DRY_RUN=0
FORCE=0
REMOVE=0

usage() {
    cat << EOF
Usage: ${PROG} [options]
  -c, --config FILE  config file (default: ${CONFIG_FILE})
  -n, --dry-run      print what would be applied, change nothing
  -f, --force        apply even if the sanity checks fail
      --remove       remove all rules and sets created by ${PROG}
  -h, --help         show this help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        -c|--config) CONFIG_FILE="${2:?--config needs a file}"; shift 2 ;;
        -n|--dry-run) DRY_RUN=1; shift ;;
        -f|--force) FORCE=1; shift ;;
        --remove) REMOVE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done

# ---- defaults (override in the config file) --------------------------------
BASE_URL="https://raw.githubusercontent.com/TripleA150/RU-Blacklist/main/output/txt"
BACKEND="nftables"          # nftables | ipset
BLOCK_GOV_INPUT="yes"       # drop new inbound connections from government networks
BLOCK_VK_FORWARD="yes"      # reject forwarded (VPN client) traffic to VK/MAX networks
BLOCK_VK_OUTPUT="no"        # reject the server's own traffic to VK/MAX networks
VPN_IFACES=""               # e.g. "wg0 awg0"; empty = all forwarded traffic
ALLOW_PREFIXES=""           # never blocked inbound, e.g. "198.51.100.7 2001:db8::/48"
MIN_GOV_ENTRIES=300         # refuse government lists smaller than this
MIN_VK_ENTRIES=20           # refuse VK lists smaller than this
MAX_SHRINK_PERCENT=50       # refuse a list that lost more entries than this vs. the last run
STATE_DIR="/var/lib/ru-blacklist"
NFT_TABLE="ru_blacklist"
IPSET_PREFIX="ru-bl"
CHAIN_PREFIX="RU_BL"

if [ -f "${CONFIG_FILE}" ]; then
    # shellcheck source=/dev/null
    . "${CONFIG_FILE}"
elif [ "${CONFIG_FILE}" != "/etc/ru-blacklist.conf" ]; then
    echo "${PROG}: config file ${CONFIG_FILE} not found" >&2
    exit 2
fi

log() { echo "${PROG}: $*" >&2; }
die() { log "ERROR: $*"; exit 1; }
is_yes() { case "$1" in [Yy][Ee][Ss]|[Yy]|1|[Tt][Rr][Uu][Ee]) return 0 ;; *) return 1 ;; esac; }

case "${BACKEND}" in
    nftables|ipset) ;;
    *) die "BACKEND must be 'nftables' or 'ipset', got '${BACKEND}'" ;;
esac

if [ "${DRY_RUN}" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
    die "must run as root (or use --dry-run)"
fi

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/${PROG}.XXXXXX")"
trap 'rm -rf "${WORK_DIR}"' EXIT
trap 'exit 130' INT TERM

if [ "${DRY_RUN}" -eq 0 ]; then
    mkdir -p "${STATE_DIR}"
    chmod 755 "${STATE_DIR}"
    if command -v flock > /dev/null 2>&1; then
        exec 9> "${STATE_DIR}/lock"
        flock -n 9 || die "another ${PROG} run is in progress"
    fi
fi

# ---- removal -----------------------------------------------------------------
iptables_cmds() {
    command -v iptables > /dev/null 2>&1 && echo iptables
    command -v ip6tables > /dev/null 2>&1 && echo ip6tables
    return 0
}

remove_all() {
    if command -v nft > /dev/null 2>&1 && nft list table inet "${NFT_TABLE}" > /dev/null 2>&1; then
        nft delete table inet "${NFT_TABLE}"
        log "removed nftables table inet ${NFT_TABLE}"
    fi
    for ipt in $(iptables_cmds); do
        for hook in INPUT FORWARD OUTPUT; do
            chain="${CHAIN_PREFIX}_${hook}"
            while "${ipt}" -D "${hook}" -j "${chain}" 2> /dev/null; do :; done
            if "${ipt}" -n -L "${chain}" > /dev/null 2>&1; then
                "${ipt}" -F "${chain}"
                "${ipt}" -X "${chain}"
                log "removed ${ipt} chain ${chain}"
            fi
        done
    done
    if command -v ipset > /dev/null 2>&1; then
        for set in gov-v4 gov-v6 vk-v4 vk-v6; do
            for name in "${IPSET_PREFIX}-${set}-tmp" "${IPSET_PREFIX}-${set}"; do
                if ipset list -n "${name}" > /dev/null 2>&1; then
                    ipset destroy "${name}"
                    log "removed ipset ${name}"
                fi
            done
        done
    fi
}

if [ "${REMOVE}" -eq 1 ]; then
    [ "${DRY_RUN}" -eq 1 ] && die "--remove cannot be combined with --dry-run"
    remove_all
    rm -f "${STATE_DIR}"/*.txt "${STATE_DIR}/last-applied"
    exit 0
fi

# ---- download and validate -----------------------------------------------------
fetch() {
    url="${BASE_URL%/}/$1"
    if command -v curl > /dev/null 2>&1; then
        curl -fsSL --retry 3 --retry-delay 5 --connect-timeout 20 --max-time 120 -o "$2" "${url}"
    elif command -v wget > /dev/null 2>&1; then
        wget -q -T 60 -t 3 -O "$2" "${url}"
    else
        die "neither curl nor wget is installed"
    fi
}

# clean_list FILE FAMILY OUTPUT: keep prefixes only; fail on any line that is not one.
clean_list() {
    awk -v family="$2" '
        { sub(/#.*/, ""); gsub(/[ \t\r]+/, "") }
        $0 == "" { next }
        family == 4 && $0 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/ { print; next }
        family == 6 && $0 ~ /^[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*(\/[0-9]+)?$/ { print; next }
        { bad++; if (bad <= 5) printf "invalid line %d: %s\n", NR, $0 > "/dev/stderr" }
        END { exit bad > 0 }
    ' "$1" > "$3"
}

count_entries() { grep -c . "$1" || true; }

# get_list NAME FAMILY: download, validate, fall back to cache; prints the cleaned file path.
get_list() {
    raw="${WORK_DIR}/$1.raw"
    clean="${WORK_DIR}/$1"
    if fetch "$1" "${raw}" && clean_list "${raw}" "$2" "${clean}"; then
        :
    elif [ -s "${STATE_DIR}/$1" ]; then
        log "WARNING: could not get a valid $1, reusing the cached copy from the last run"
        cp "${STATE_DIR}/$1" "${clean}"
    else
        die "could not get a valid $1 and there is no cached copy"
    fi
    echo "${clean}"
}

# check_list FILE NAME MIN_ENTRIES: refuse too small or suddenly shrunken lists.
check_list() {
    count="$(count_entries "$1")"
    problem=""
    if [ "${count}" -lt "$3" ]; then
        problem="$2 has ${count} entries, expected at least $3"
    elif [ -s "${STATE_DIR}/$2" ]; then
        previous="$(count_entries "${STATE_DIR}/$2")"
        if [ $((count * 100)) -lt $((previous * (100 - MAX_SHRINK_PERCENT))) ]; then
            problem="$2 shrank from ${previous} to ${count} entries (limit ${MAX_SHRINK_PERCENT}%)"
        fi
    fi
    if [ -n "${problem}" ]; then
        if [ "${FORCE}" -eq 1 ]; then
            log "WARNING: ${problem}; applying anyway (--force)"
        else
            log "ERROR: ${problem}; keeping the current rules (use --force to override)"
            exit 3
        fi
    fi
}

EMPTY="${WORK_DIR}/empty"
: > "${EMPTY}"
GOV_V4="${EMPTY}"; GOV_V6="${EMPTY}"; VK_V4="${EMPTY}"; VK_V6="${EMPTY}"

if is_yes "${BLOCK_GOV_INPUT}"; then
    GOV_V4="$(get_list blacklist-v4.txt 4)"
    GOV_V6="$(get_list blacklist-v6.txt 6)"
    check_list "${GOV_V4}" blacklist-v4.txt "${MIN_GOV_ENTRIES}"
fi
if is_yes "${BLOCK_VK_FORWARD}" || is_yes "${BLOCK_VK_OUTPUT}"; then
    VK_V4="$(get_list blacklist-vk-v4.txt 4)"
    VK_V6="$(get_list blacklist-vk-v6.txt 6)"
    check_list "${VK_V4}" blacklist-vk-v4.txt "${MIN_VK_ENTRIES}"
fi

ALLOW_V4=""
ALLOW_V6=""
for prefix in ${ALLOW_PREFIXES}; do
    case "${prefix}" in
        *:*) ALLOW_V6="${ALLOW_V6:+${ALLOW_V6}, }${prefix}" ;;
        *) ALLOW_V4="${ALLOW_V4:+${ALLOW_V4}, }${prefix}" ;;
    esac
done

# ---- nftables backend ----------------------------------------------------------
nft_set() {
    echo "    set $1 {"
    echo "        type $2"
    echo "        flags interval"
    if [ -s "$3" ]; then
        echo "        elements = {"
        awk 'NF { if (n++) printf ",\n"; printf "            %s", $1 } END { if (n) printf "\n" }' "$3"
        echo "        }"
    fi
    echo "    }"
}

nft_ifaces() {
    [ -n "${VPN_IFACES}" ] || return 0
    printf 'iifname { '
    first=1
    for iface in ${VPN_IFACES}; do
        [ "${first}" -eq 1 ] || printf ', '
        printf '"%s"' "${iface}"
        first=0
    done
    printf ' } '
}

nft_reject() {  # MATCH
    echo "        $1 meta l4proto tcp counter reject with tcp reset"
    echo "        $1 counter reject with icmpx type admin-prohibited"
}

build_nft() {
    echo "# Generated by ${PROG}; the whole table is replaced atomically on every run."
    echo "table inet ${NFT_TABLE}"
    echo "delete table inet ${NFT_TABLE}"
    echo "table inet ${NFT_TABLE} {"
    nft_set gov_v4 ipv4_addr "${GOV_V4}"
    nft_set gov_v6 ipv6_addr "${GOV_V6}"
    nft_set vk_v4 ipv4_addr "${VK_V4}"
    nft_set vk_v6 ipv6_addr "${VK_V6}"
    if is_yes "${BLOCK_GOV_INPUT}"; then
        echo "    chain input {"
        echo "        type filter hook input priority -10; policy accept;"
        [ -z "${ALLOW_V4}" ] || echo "        ct state new ip saddr { ${ALLOW_V4} } return"
        [ -z "${ALLOW_V6}" ] || echo "        ct state new ip6 saddr { ${ALLOW_V6} } return"
        echo "        ct state new ip saddr @gov_v4 counter drop"
        echo "        ct state new ip6 saddr @gov_v6 counter drop"
        echo "    }"
    fi
    if is_yes "${BLOCK_VK_FORWARD}"; then
        ifaces="$(nft_ifaces)"
        echo "    chain forward {"
        echo "        type filter hook forward priority -10; policy accept;"
        nft_reject "${ifaces}ip daddr @vk_v4"
        nft_reject "${ifaces}ip6 daddr @vk_v6"
        echo "    }"
    fi
    if is_yes "${BLOCK_VK_OUTPUT}"; then
        echo "    chain output {"
        echo "        type filter hook output priority -10; policy accept;"
        nft_reject "ip daddr @vk_v4"
        nft_reject "ip6 daddr @vk_v6"
        echo "    }"
    fi
    echo "}"
}

apply_nftables() {
    command -v nft > /dev/null 2>&1 || die "nft is not installed (apt install nftables)"
    build_nft > "${WORK_DIR}/ruleset.nft"
    if [ "${DRY_RUN}" -eq 1 ]; then
        cat "${WORK_DIR}/ruleset.nft"
        return 0
    fi
    nft -f "${WORK_DIR}/ruleset.nft" || die "nft rejected the ruleset; the previous rules are still active"
}

# ---- ipset + iptables backend --------------------------------------------------
ipset_load() {  # SET_SUFFIX FAMILY FILE
    name="${IPSET_PREFIX}-$1"
    echo "create ${name} hash:net family $2 hashsize 1024 maxelem 262144 -exist"
    echo "create ${name}-tmp hash:net family $2 hashsize 1024 maxelem 262144 -exist"
    echo "flush ${name}-tmp"
    awk -v set="${name}-tmp" 'NF { print "add " set " " $1 }' "$3"
    echo "swap ${name}-tmp ${name}"
    echo "destroy ${name}-tmp"
}

build_ipset() {
    ipset_load gov-v4 inet "${GOV_V4}"
    ipset_load gov-v6 inet6 "${GOV_V6}"
    ipset_load vk-v4 inet "${VK_V4}"
    ipset_load vk-v6 inet6 "${VK_V6}"
}

build_iptables() {  # 4|6
    v="$1"
    if [ "${v}" = 4 ]; then allow="${ALLOW_V4}"; icmp="icmp-admin-prohibited"; else allow="${ALLOW_V6}"; icmp="icmp6-adm-prohibited"; fi
    in="${CHAIN_PREFIX}_INPUT"; fwd="${CHAIN_PREFIX}_FORWARD"; out="${CHAIN_PREFIX}_OUTPUT"
    echo "*filter"
    echo ":${in} - [0:0]"
    echo ":${fwd} - [0:0]"
    echo ":${out} - [0:0]"
    if is_yes "${BLOCK_GOV_INPUT}"; then
        for prefix in $(echo "${allow}" | tr ',' ' '); do
            echo "-A ${in} -s ${prefix} -j RETURN"
        done
        echo "-A ${in} -m conntrack --ctstate NEW -m set --match-set ${IPSET_PREFIX}-gov-v${v} src -j DROP"
    fi
    if is_yes "${BLOCK_VK_FORWARD}"; then
        for iface in ${VPN_IFACES:-ANY}; do
            match=""
            [ "${iface}" = ANY ] || match="-i ${iface} "
            echo "-A ${fwd} ${match}-p tcp -m set --match-set ${IPSET_PREFIX}-vk-v${v} dst -j REJECT --reject-with tcp-reset"
            echo "-A ${fwd} ${match}-m set --match-set ${IPSET_PREFIX}-vk-v${v} dst -j REJECT --reject-with ${icmp}"
        done
    fi
    if is_yes "${BLOCK_VK_OUTPUT}"; then
        echo "-A ${out} -p tcp -m set --match-set ${IPSET_PREFIX}-vk-v${v} dst -j REJECT --reject-with tcp-reset"
        echo "-A ${out} -m set --match-set ${IPSET_PREFIX}-vk-v${v} dst -j REJECT --reject-with ${icmp}"
    fi
    echo "COMMIT"
}

apply_ipset() {
    build_ipset > "${WORK_DIR}/ipset.restore"
    build_iptables 4 > "${WORK_DIR}/iptables.rules"
    build_iptables 6 > "${WORK_DIR}/ip6tables.rules"
    if [ "${DRY_RUN}" -eq 1 ]; then
        cat "${WORK_DIR}/ipset.restore" "${WORK_DIR}/iptables.rules" "${WORK_DIR}/ip6tables.rules"
        return 0
    fi
    command -v ipset > /dev/null 2>&1 || die "ipset is not installed (apt install ipset)"
    command -v iptables > /dev/null 2>&1 || die "iptables is not installed"

    # Sets first (atomic swap per set), then the chains that reference them.
    ipset restore < "${WORK_DIR}/ipset.restore" || die "ipset restore failed; the previous sets are still active"
    for ipt in $(iptables_cmds); do
        if [ "${ipt}" = iptables ]; then rules="${WORK_DIR}/iptables.rules"; else rules="${WORK_DIR}/ip6tables.rules"; fi
        # --noflush keeps the rest of the table; declared chains are flushed and refilled atomically.
        "${ipt}-restore" --noflush < "${rules}" || die "${ipt}-restore failed"
        for hook in INPUT FORWARD OUTPUT; do
            "${ipt}" -C "${hook}" -j "${CHAIN_PREFIX}_${hook}" 2> /dev/null \
                || "${ipt}" -I "${hook}" 1 -j "${CHAIN_PREFIX}_${hook}"
        done
    done
}

# ---- apply ---------------------------------------------------------------------
if [ "${BACKEND}" = nftables ]; then
    apply_nftables
else
    apply_ipset
fi

[ "${DRY_RUN}" -eq 1 ] && exit 0

for list in blacklist-v4.txt blacklist-v6.txt blacklist-vk-v4.txt blacklist-vk-v6.txt; do
    if [ -f "${WORK_DIR}/${list}" ]; then
        cp "${WORK_DIR}/${list}" "${STATE_DIR}/${list}.new"
        mv -f "${STATE_DIR}/${list}.new" "${STATE_DIR}/${list}"
    fi
done
summary="backend=${BACKEND} gov_v4=$(count_entries "${GOV_V4}") gov_v6=$(count_entries "${GOV_V6}") vk_v4=$(count_entries "${VK_V4}") vk_v6=$(count_entries "${VK_V6}")"
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) ${summary}" > "${STATE_DIR}/last-applied"
log "applied: ${summary}"
