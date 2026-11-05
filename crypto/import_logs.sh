#!/usr/bin/env bash
# import_logs.sh - on the PC: check and open an export.
#   ./import_logs.sh EXPORT.tar pc_private.pem pi_public.pem OUT_DIR
# Checks the Pi's signature first, then decrypts, then compares the SHA-256. Any failure:
# exit 1 and nothing written.
set -euo pipefail
IN="$1"; PRIV="$2"; PIPUB="$3"; OUTD="$4"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
tar -C "$W" -xf "$IN" key.enc data.enc sig
cat "$W/key.enc" "$W/data.enc" > "$W/signed"
if ! openssl pkeyutl -verify -rawin -pubin -inkey "$PIPUB" -in "$W/signed" -sigfile "$W/sig" >/dev/null 2>&1; then
  echo "signature check failed: not from this Pi, or changed on the way" >&2; exit 1
fi
if ! openssl pkeyutl -decrypt -inkey "$PRIV" -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -in "$W/key.enc" -out "$W/key" 2>/dev/null; then
  echo "cannot unwrap the key with this private key" >&2; exit 1
fi
KEY=$(sed -n 1p "$W/key"); IV=$(sed -n 2p "$W/key"); SHA=$(sed -n 3p "$W/key"); NAME=$(basename "$(sed -n 4p "$W/key")")
openssl enc -d -aes-256-cbc -K "$KEY" -iv "$IV" -in "$W/data.enc" -out "$W/plain"
[ "$(sha256sum "$W/plain" | cut -d' ' -f1)" = "$SHA" ] || { echo "SHA-256 mismatch" >&2; exit 1; }
mkdir -p "$OUTD"; cp "$W/plain" "$OUTD/$NAME"
echo "imported $NAME: signature and SHA-256 ok"
