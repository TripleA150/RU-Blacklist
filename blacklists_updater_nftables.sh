#!/bin/sh
# Generates nftables blacklist configurations from the text blacklists.

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "${SCRIPT_DIR}/blacklists_updater_common.subr"
OUTPUT_DIR="${SCRIPT_DIR}/blacklists_nftables"

mkdir -p "${OUTPUT_DIR}" "${BLACKLISTS_DIR}"

echo "Generating nftables blacklists..."

build_vk_name_blacklists

# generate_nft INPUT OUTPUT FAMILY PROFILE
generate_nft() {
    _tmp="$(make_tmp)"
    "${PYTHON}" "${SCRIPT_DIR}/generate_nft_blacklist.py" --quiet --family "$3" --profile "$4" "$1" "${_tmp}"
    publish_file "${_tmp}" "$2"
    echo "✓ Generated: $2"
}

# Mixed IPv4/IPv6 files (recommended single-file load) and per-family files.
generate_nft "${BLACKLIST_FILE}" "${OUTPUT_DIR}/blacklist.nft" both vm_input
generate_nft "${BLACKLIST_V4_FILE}" "${OUTPUT_DIR}/blacklist-v4.nft" 4 vm_input
generate_nft "${BLACKLIST_V6_FILE}" "${OUTPUT_DIR}/blacklist-v6.nft" 6 vm_input

# VK-only lists from the narrowed MAX/VK service name filter.
generate_nft "${BLACKLIST_VK_FILE}" "${OUTPUT_DIR}/blacklist-vk.nft" both vk_forward
generate_nft "${BLACKLIST_VK_V4_FILE}" "${OUTPUT_DIR}/blacklist-vk-v4.nft" 4 vk_forward
generate_nft "${BLACKLIST_VK_V6_FILE}" "${OUTPUT_DIR}/blacklist-vk-v6.nft" 6 vk_forward

echo "nftables blacklists generated successfully!"
echo ""
echo "VM incoming block examples (load either blacklist.nft or the -v4/-v6 pair):"
echo "  sudo nft -f ${OUTPUT_DIR}/blacklist.nft"
echo "  sudo nft add chain inet filter input '{ type filter hook input priority 0; policy accept; }'"
echo "  sudo nft add rule inet filter input ip saddr @blacklist_v4 counter reject"
echo "  sudo nft add rule inet filter input ip6 saddr @blacklist_v6 counter reject"
echo ""
echo "VK outbound block examples for VPN clients via NAT (nftables):"
echo "  sudo nft -f ${OUTPUT_DIR}/blacklist-vk.nft"
echo "  sudo nft add chain inet filter forward '{ type filter hook forward priority 0; policy accept; }'"
echo "  sudo nft add rule inet filter forward iifname \"<VPN_IFACE>\" ip daddr @blacklist_vk_v4 counter reject"
echo "  sudo nft add rule inet filter forward iifname \"<VPN_IFACE>\" ip6 daddr @blacklist_vk_v6 counter reject"
echo ""
echo "Tip: Do not install Messenger MAX on the same phone/device that has VPN access configured."
