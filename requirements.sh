#!/bin/sh
# Installs the Python dependencies. Inside a virtualenv a plain install is used;
# for a system Python that refuses it (PEP 668) the user site is tried instead.

set -eu

cd "$(dirname "$0")"

if python3 -m pip install -r requirements.txt; then
    exit 0
fi
echo "Plain pip install failed; retrying with --user --break-system-packages (PEP 668)." >&2
python3 -m pip install --user --break-system-packages -r requirements.txt
