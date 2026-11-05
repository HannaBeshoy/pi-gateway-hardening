#!/usr/bin/env bash
# harden.sh - harden a Raspberry Pi that runs the sensor logger (IT Security course project).
#
#   sudo ./harden.sh --key ops.pub [--lan 192.168.1.0/24] [--tunnel-only] [--luks SIZE_MB]
#                    [--root DIR] [--dry-run]
#
# Steps (each can be re-run safely):
#   1. users: "sensor" (system user, no login) runs the logger; "ops" is the operator,
#      in groups ssh-users and sensor-ops
#   2. sudo: sensor-ops may only manage the logger service and shut down (checked by visudo)
#   3. SSH: key login only, no root, only ssh-users (checked by sshd -t). Refuses to turn
#      passwords off unless ops already has a key, so it cannot lock you out.
#   4. firewall: nftables, drop by default; SSH, the logger's ports and DHCP from the LAN only.
#      --tunnel-only also closes the logger's ports: then they are reached through SSH only
#   5. logs: an encrypted LUKS volume mounted at /var/lib/sensor-logs (optional, --luks)
#   6. permissions: log directory owned by sensor, mode 0750
# --root DIR writes the configuration under DIR instead of / (for testing); --dry-run
# only prints what would change.
set -euo pipefail

ROOT=/ ; LAN=192.168.0.0/16 ; KEY="" ; LUKS_MB=0 ; DRY=0 ; TUNNEL_ONLY=0
HERE="$(cd "$(dirname "$0")" && pwd)"
while [ $# -gt 0 ]; do
  case "$1" in
    --root) ROOT="$2"; shift 2 ;;
    --lan) LAN="$2"; shift 2 ;;
    --key) KEY="$2"; shift 2 ;;
    --luks) LUKS_MB="$2"; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    --tunnel-only) TUNNEL_ONLY=1; shift ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" = 0 ] || [ "$ROOT" != / ] || { echo "run as root (sudo)" >&2; exit 1; }
R="${ROOT%/}"
say()  { echo "[harden] $*"; }
run()  { if [ $DRY = 1 ]; then echo "  would run: $*"; else "$@"; fi; }
put()  {  # put SRC DEST MODE: install a file only if it changed
  local src="$1" dest="$R$2" mode="$3"
  if [ -f "$dest" ] && cmp -s "$src" "$dest"; then say "unchanged $2"; return; fi
  if [ $DRY = 1 ]; then echo "  would write $2"; return; fi
  mkdir -p "$(dirname "$dest")"; install -m "$mode" "$src" "$dest"; say "wrote $2"
}
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# --- 1. users and groups ------------------------------------------------------------
if [ "$ROOT" = / ]; then
  for g in ssh-users sensor-ops; do getent group "$g" >/dev/null || run groupadd "$g"; done
  id sensor >/dev/null 2>&1 || run useradd --system --no-create-home --shell /usr/sbin/nologin sensor
  id ops >/dev/null 2>&1 || run useradd --create-home --shell /bin/bash ops
  run usermod -aG ssh-users,sensor-ops ops
  # a new account is "locked" (!) and sshd refuses locked accounts even with a key;
  # '*' means: no password can ever match, but the account is not locked
  [ $DRY = 1 ] || { getent shadow ops | cut -d: -f2 | grep -q '^!' && run usermod -p '*' ops; } || true
  [ $DRY = 1 ] || passwd -S sensor 2>/dev/null | grep -q " L " || run passwd -l sensor >/dev/null
  say "users: sensor (no login), ops (ssh-users, sensor-ops)"
fi

# --- 2. sudo ------------------------------------------------------------------------
visudo -cf "$HERE/config/sensor-ops.sudoers" >/dev/null || { echo "sudoers file does not pass visudo" >&2; exit 1; }
put "$HERE/config/sensor-ops.sudoers" /etc/sudoers.d/sensor-ops 0440

# --- 3. SSH ---------------------------------------------------------------------------
OPS_HOME="$R/home/ops"
if [ -n "$KEY" ]; then
  grep -qE '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp[0-9]+) [A-Za-z0-9+/=]+' "$KEY" || { echo "$KEY is not an SSH public key" >&2; exit 1; }
  if [ $DRY = 0 ]; then
    mkdir -p "$OPS_HOME/.ssh"
    touch "$OPS_HOME/.ssh/authorized_keys"
    grep -qxF "$(cat "$KEY")" "$OPS_HOME/.ssh/authorized_keys" || cat "$KEY" >> "$OPS_HOME/.ssh/authorized_keys"
    chmod 700 "$OPS_HOME/.ssh"; chmod 600 "$OPS_HOME/.ssh/authorized_keys"
    [ "$ROOT" = / ] && chown -R ops:ops "$OPS_HOME/.ssh"
  fi
  say "key for ops installed"
fi
if [ ! -s "$OPS_HOME/.ssh/authorized_keys" ] && [ $DRY = 0 ]; then
  echo "no SSH key for ops yet: give one with --key, or turning passwords off would lock you out" >&2
  exit 1
fi
put "$HERE/config/10-sensor-gateway.conf" /etc/ssh/sshd_config.d/10-sensor-gateway.conf 0644
if [ "$ROOT" = / ] && [ $DRY = 0 ]; then
  sshd -t || { echo "sshd configuration invalid: not reloading" >&2; exit 1; }
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
fi

# --- 4. firewall ----------------------------------------------------------------------
[[ "$LAN" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]] || { echo "--lan must look like 192.168.1.0/24" >&2; exit 1; }
sed "s#LAN#$LAN#g" "$HERE/config/sensor-gateway.nft" > "$TMP/fw.nft"
[ $TUNNEL_ONLY = 1 ] && sed -i '/dport 560[01] /d' "$TMP/fw.nft"
put "$TMP/fw.nft" /etc/nftables.d/sensor-gateway.nft 0600
if [ "$ROOT" = / ] && [ $DRY = 0 ]; then
  nft -c -f "$R/etc/nftables.d/sensor-gateway.nft" && nft -f "$R/etc/nftables.d/sensor-gateway.nft"
  grep -q 'include "/etc/nftables.d/\*.nft"' /etc/nftables.conf 2>/dev/null || echo 'include "/etc/nftables.d/*.nft"' >> /etc/nftables.conf
  systemctl enable nftables >/dev/null 2>&1 || true
fi

# --- 5. encrypted log volume -------------------------------------------------------------
if [ "$LUKS_MB" -gt 0 ]; then
  IMG="$R/var/lib/sensor-logs.luks"; KEYF="$R/root/sensor-logs.key"; MNT="$R/var/lib/sensor-logs"
  if [ ! -f "$IMG" ] && [ $DRY = 0 ]; then
    mkdir -p "$(dirname "$IMG")" "$(dirname "$KEYF")"
    umask 077; head -c 64 /dev/urandom > "$KEYF"; umask 022
    dd if=/dev/zero of="$IMG" bs=1M count="$LUKS_MB" status=none
    cryptsetup luksFormat --batch-mode --type luks2 --key-file "$KEYF" "$IMG"
    cryptsetup open --key-file "$KEYF" "$IMG" sensor-logs
    mkfs.ext4 -q /dev/mapper/sensor-logs
    cryptsetup close sensor-logs
    say "created LUKS2 volume ${LUKS_MB} MB, key in /root/sensor-logs.key (keep a copy elsewhere)"
  fi
  if [ "$ROOT" = / ] && [ $DRY = 0 ]; then
    [ -e /dev/mapper/sensor-logs ] || cryptsetup open --key-file "$KEYF" "$IMG" sensor-logs
    mkdir -p "$MNT"; mountpoint -q "$MNT" || mount /dev/mapper/sensor-logs "$MNT"
    grep -q '^sensor-logs ' /etc/crypttab 2>/dev/null || echo "sensor-logs $IMG $KEYF luks" >> /etc/crypttab
    grep -q '/dev/mapper/sensor-logs' /etc/fstab || echo "/dev/mapper/sensor-logs $MNT ext4 defaults,nofail 0 2" >> /etc/fstab
  fi
fi

# --- 6. permissions -------------------------------------------------------------------------
if [ $DRY = 0 ]; then
  mkdir -p "$R/var/lib/sensor-logs"
  chmod 0750 "$R/var/lib/sensor-logs"
  [ "$ROOT" = / ] && chown sensor:sensor "$R/var/lib/sensor-logs"
fi
say "done"
