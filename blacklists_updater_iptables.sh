#!/bin/sh
# Generates ipset restore files for iptables/ip6tables from the text blacklists.
#
# The files can be restored again and again, even while iptables rules use the
# set: entries are loaded into "<set>-tmp", which is then atomically swapped
# with "<set>" and destroyed.

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "${SCRIPT_DIR}/blacklists_updater_common.subr"

# Output directory and files
iptables_output_dir="${SCRIPT_DIR}/blacklists_iptables"
iptables_v4_output_file="${iptables_output_dir}/blacklist-v4.ipset"
iptables_v6_output_file="${iptables_output_dir}/blacklist-v6.ipset"
iptables_vk_v4_output_file="${iptables_output_dir}/blacklist-vk-v4.ipset"
iptables_vk_v6_output_file="${iptables_output_dir}/blacklist-vk-v6.ipset"

# Fixed set parameters: "create -exist" only succeeds for an identical existing set.
IPSET_HASHSIZE=1024
IPSET_MAXELEM=65536

# Create required directories if they don't exist
mkdir -p "${iptables_output_dir}" "${BLACKLISTS_DIR}"
build_vk_name_blacklists

# generate_ipset_config INPUT OUTPUT DESCRIPTION SET_NAME FAMILY
generate_ipset_config() {
    input_file="$1"
    output_file="$2"
    ip_version="$3"
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

    tmp="$(make_tmp)"
    {
        cat << EOF
# IPSet blacklist configuration ${ip_version}
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
    } > "${tmp}"
    publish_file "${tmp}" "${output_file}"

    echo "✓ Generated ${ip_version}: ${output_file}"
    echo "  Total entries: ${count}"
}

# Generate ipset configurations from blacklist files
generate_ipset_config "${BLACKLIST_V4_FILE}" "${iptables_v4_output_file}" "(IPv4 only)" "blacklist-v4" "inet"
generate_ipset_config "${BLACKLIST_V6_FILE}" "${iptables_v6_output_file}" "(IPv6 only)" "blacklist-v6" "inet6"
generate_ipset_config "${BLACKLIST_VK_V4_FILE}" "${iptables_vk_v4_output_file}" "(VK names, IPv4 only)" "blacklist-vk-v4" "inet"
generate_ipset_config "${BLACKLIST_VK_V6_FILE}" "${iptables_vk_v6_output_file}" "(VK names, IPv6 only)" "blacklist-vk-v6" "inet6"

echo ""
echo "VK outgoing block examples (iptables/ipset):"
echo "  ipset restore < ${iptables_vk_v4_output_file}"
echo "  ipset restore < ${iptables_vk_v6_output_file}"
echo "  iptables -I OUTPUT -m set --match-set blacklist-vk-v4 dst -j REJECT"
echo "  iptables -I FORWARD -m set --match-set blacklist-vk-v4 dst -j REJECT"
echo "  ip6tables -I OUTPUT -m set --match-set blacklist-vk-v6 dst -j REJECT"
echo "  ip6tables -I FORWARD -m set --match-set blacklist-vk-v6 dst -j REJECT"
echo ""
echo "Tip: Do not install Messenger MAX on the same phone/device that has VPN access configured."
