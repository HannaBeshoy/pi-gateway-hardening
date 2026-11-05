#!/usr/bin/env bash
# make_keys.sh - the two key pairs of the log export.
#   ./make_keys.sh pc DIR   on the PC: RSA-4096 for encryption  -> DIR/pc_private.pem, DIR/pc_public.pem
#   ./make_keys.sh pi DIR   on the Pi: Ed25519 for signing       -> DIR/pi_private.pem, DIR/pi_public.pem
# Each private key stays where it was made; the public keys are swapped (PC's to the Pi, Pi's to the PC).
set -euo pipefail
WHO="$1"; D="${2:-.}"; mkdir -p "$D"
umask 077
case "$WHO" in
  pc) openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$D/pc_private.pem" 2>/dev/null ;;
  pi) openssl genpkey -algorithm ED25519 -out "$D/pi_private.pem" ;;
  *) echo "usage: $0 pc|pi DIR" >&2; exit 2 ;;
esac
umask 022
openssl pkey -in "$D/${WHO}_private.pem" -pubout -out "$D/${WHO}_public.pem"
echo "$D/${WHO}_private.pem stays here; copy $D/${WHO}_public.pem to the other side"
