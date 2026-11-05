#!/usr/bin/env bash
# ssh_key_to_pem.sh - the course's key-transformation lab: use the PC's existing ssh-keygen
# RSA key for the log export instead of making a second key pair.
#   ./ssh_key_to_pem.sh ~/.ssh/id_rsa DIR   -> DIR/pc_private.pem (PKCS#8), DIR/pc_public.pem
# ssh-keygen writes its own private-key format; OpenSSL wants PEM. ssh-keygen -e -m pkcs8
# exports the public half, and a copy of the private key rewritten with -m PEM is read by
# openssl pkcs8 -topk8. The original key file is not touched.
set -euo pipefail
SRC="$1"; D="${2:-.}"; mkdir -p "$D"
head -c 40 "$SRC.pub" 2>/dev/null | grep -q '^ssh-rsa ' || { echo "$SRC.pub is not an RSA key: the export needs RSA for encryption" >&2; exit 1; }
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
umask 077
cp "$SRC" "$W/k"; ssh-keygen -p -N '' -m PEM -f "$W/k" -q </dev/null      # asks for the passphrase if it has one
openssl pkcs8 -topk8 -nocrypt -in "$W/k" -out "$D/pc_private.pem"
umask 022
ssh-keygen -e -m pkcs8 -f "$SRC.pub" > "$D/pc_public.pem"
echo "converted: $D/pc_private.pem stays on the PC; copy $D/pc_public.pem to the Pi"
