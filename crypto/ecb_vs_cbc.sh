#!/usr/bin/env bash
# ecb_vs_cbc.sh - the course's DES lab, with AES: why ECB mode must not be used for logs.
# Sensor logs repeat a lot (the same temperature line many times). In ECB every equal
# 16-byte block encrypts to the same ciphertext block, so the pattern shows through;
# in CBC each block is mixed with the previous ciphertext, so nothing repeats.
set -euo pipefail
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
KEY=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
IV=0f0e0d0c0b0a09080706050403020100
dd if=/dev/zero of="$W/zeros" bs=16 count=6 status=none            # 6 identical blocks, as in the lab
openssl enc -aes-256-ecb -nopad -K $KEY -in "$W/zeros" -out "$W/ecb"
openssl enc -aes-256-cbc -nopad -K $KEY -iv $IV -in "$W/zeros" -out "$W/cbc"
ecb=$(od -An -tx1 -v -w16 "$W/ecb" | sort -u | wc -l); cbc=$(od -An -tx1 -v -w16 "$W/cbc" | sort -u | wc -l)
echo "6 identical plaintext blocks -> ECB: $ecb distinct ciphertext block(s), CBC: $cbc"
echo "ECB:"; od -An -tx1 -v -w16 "$W/ecb"
echo "CBC:"; od -An -tx1 -v -w16 "$W/cbc"
[ "$ecb" = 1 ] && [ "$cbc" = 6 ]
