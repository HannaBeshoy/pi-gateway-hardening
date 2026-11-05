#!/usr/bin/env bash
# export_logs.sh - on the Pi: pack a log file so that only the PC can read it, and the PC
# can tell it really came from this Pi and was not changed.
#   ./export_logs.sh LOG.csv pc_public.pem pi_private.pem OUT.tar
#
# The course's OpenSSL labs put together:
#   1. confidentiality: a fresh random AES-256 key and IV; the file encrypted with AES-256-CBC
#      (enc lab); the key, the IV and the file's SHA-256 encrypted with the PC's RSA public key,
#      OAEP padding (rsautl lab). RSA alone cannot encrypt a whole file; AES alone would need
#      a secret shared with the Pi.
#   2. integrity and origin: an Ed25519 signature by the Pi over both encrypted parts. Anyone
#      can encrypt to the PC's public key; only this Pi can sign.
set -euo pipefail
LOG="$1"; PUB="$2"; SIGNKEY="$3"; OUT="$4"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
KEY=$(openssl rand -hex 32); IV=$(openssl rand -hex 16)
openssl enc -aes-256-cbc -K "$KEY" -iv "$IV" -in "$LOG" -out "$W/data.enc"
printf '%s\n%s\n%s\n%s\n' "$KEY" "$IV" "$(sha256sum "$LOG" | cut -d' ' -f1)" "$(basename "$LOG")" |
  openssl pkeyutl -encrypt -pubin -inkey "$PUB" -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -out "$W/key.enc"
cat "$W/key.enc" "$W/data.enc" > "$W/signed"
openssl pkeyutl -sign -rawin -inkey "$SIGNKEY" -in "$W/signed" -out "$W/sig"
tar -C "$W" -cf "$OUT" key.enc data.enc sig
echo "exported $(basename "$LOG") -> $OUT"
