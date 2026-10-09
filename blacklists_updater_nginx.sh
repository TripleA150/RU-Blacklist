#!/bin/sh
# Generates nginx "deny" include files from the text blacklists.

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "${SCRIPT_DIR}/blacklists_updater_common.subr"

# Output directory and files
nginx_output_dir="${SCRIPT_DIR}/blacklists_nginx"
nginx_output_file="${nginx_output_dir}/blacklist.conf"
nginx_v4_output_file="${nginx_output_dir}/blacklist-v4.conf"
nginx_v6_output_file="${nginx_output_dir}/blacklist-v6.conf"

# Create required directories if they don't exist
mkdir -p "${nginx_output_dir}" "${BLACKLISTS_DIR}"

# generate_nginx_config INPUT OUTPUT DESCRIPTION
generate_nginx_config() {
    tmp="$(make_tmp)"
    {
        cat << EOF
# Nginx blacklist configuration $3
# Auto-generated from $(basename "$1")
# Last updated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
#
# Usage: Include this file in your nginx server or location block:
#   include /path/to/$(basename "$2");
#

EOF
        awk 'NF { print "deny " $1 ";" }' "$1"
        echo ""
    } > "${tmp}"
    publish_file "${tmp}" "$2"

    echo "✓ Generated $3: $2"
    echo "  Total entries: $(grep -c '^deny ' "$2" || true)"
}

# Generate nginx configurations from blacklist files
generate_nginx_config "${BLACKLIST_FILE}" "${nginx_output_file}" "(mixed IPv4/IPv6)"
generate_nginx_config "${BLACKLIST_V4_FILE}" "${nginx_v4_output_file}" "(IPv4 only)"
generate_nginx_config "${BLACKLIST_V6_FILE}" "${nginx_v6_output_file}" "(IPv6 only)"
