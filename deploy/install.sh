#!/bin/sh
# Installs ru-blacklist-update with its systemd timer.
#   sudo ./deploy/install.sh            # from a clone of the repository
#   curl -fsSL https://raw.githubusercontent.com/TripleA150/RU-Blacklist/main/deploy/install.sh | sudo sh
# The config (/etc/ru-blacklist.conf) is created once and never overwritten.

set -eu

RAW_URL="${RAW_URL:-https://raw.githubusercontent.com/TripleA150/RU-Blacklist/main/deploy}"
SRC_DIR=""
# Piped into sh ("curl ... | sudo sh"), $0 is not a file: download everything instead.
if [ -f "$0" ]; then
    SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
fi

[ "$(id -u)" -eq 0 ] || { echo "install.sh: run as root" >&2; exit 1; }
command -v systemctl > /dev/null 2>&1 || { echo "install.sh: systemd is required" >&2; exit 1; }

# install_file NAME DEST MODE: copy from the clone if present, otherwise download.
install_file() {
    tmp="$(mktemp)"
    if [ -n "${SRC_DIR}" ] && [ -f "${SRC_DIR}/$1" ]; then
        cp "${SRC_DIR}/$1" "${tmp}"
    else
        curl -fsSL --retry 3 -o "${tmp}" "${RAW_URL}/$1"
    fi
    install -m "$3" "${tmp}" "$2"
    rm -f "${tmp}"
}

install_file ru-blacklist-update.sh /usr/local/sbin/ru-blacklist-update 0755
install_file ru-blacklist-update.service /etc/systemd/system/ru-blacklist-update.service 0644
install_file ru-blacklist-update.timer /etc/systemd/system/ru-blacklist-update.timer 0644
if [ ! -f /etc/ru-blacklist.conf ]; then
    install_file ru-blacklist.conf.example /etc/ru-blacklist.conf 0644
    echo "Created /etc/ru-blacklist.conf: review BACKEND, VPN_IFACES and ALLOW_PREFIXES."
fi

systemctl daemon-reload
systemctl enable ru-blacklist-update.timer

echo
echo "Installed. Next steps:"
echo "  1. Edit /etc/ru-blacklist.conf"
echo "  2. Preview:  ru-blacklist-update --dry-run | less"
echo "  3. Apply:    systemctl start ru-blacklist-update.service && journalctl -u ru-blacklist-update -n 20"
echo "  4. Timer:    systemctl start ru-blacklist-update.timer"
