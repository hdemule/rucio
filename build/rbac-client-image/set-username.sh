#!/bin/bash
# Optional: only needed when your OIDC identity maps to several Rucio accounts.
# Without an account in rucio.cfg, the server uses your identity's default account.
#
# Usage: set-username [account]   (empty input removes the account setting)
set -euo pipefail

CONFIG="${RUCIO_CONFIG:-/opt/rucio/etc/rucio.cfg}"

if (($# > 0)); then
    account="$1"
else
    read -rp "Rucio account (leave empty to use your identity's default): " account
fi

# Drop any existing account line, then add the new one right after [client].
sed -i '/^account[[:space:]]*=/d' "$CONFIG"
if [[ -n "$account" ]]; then
    sed -i "/^\[client\]/a account = ${account}" "$CONFIG"
    echo "Account set to '${account}' in ${CONFIG}"
else
    echo "Account removed from ${CONFIG}; your identity's default account will be used"
fi

# The cached token belongs to the previous account, so force a new login.
token_file="$(sed -n 's/^auth_token_file_path[[:space:]]*=[[:space:]]*//p' "$CONFIG")"
if [[ -n "$token_file" ]]; then
    rm -f "$token_file"
fi
