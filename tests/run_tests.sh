#!/usr/bin/env bash
# run_tests.sh - checks for harden.sh, the configuration files and the crypto scripts.
#   sudo bash tests/run_tests.sh              configuration (in a scratch root) and crypto
#   sudo SYSTEM_TESTS=1 bash tests/run_tests.sh   also harden this machine and run audit.sh (CI only!)
# Also, if sshd and tcpdump are installed: the logger's port read directly vs through an SSH tunnel.
#   CAPTURE_DIR=docs/captures ... keeps that capture (open it in Wireshark).
set -u
cd "$(dirname "$0")/.."
pass=0; fail=0
ok()   { echo "PASS  $1"; pass=$((pass + 1)); }
bad()  { echo "FAIL  $1"; fail=$((fail + 1)); }
check(){ if eval "$2" >/dev/null 2>&1; then ok "$1"; else bad "$1"; fi; }
W="$(mktemp -d)"; trap 'rm -rf "$W"; [ -n "${SSHD_PID:-}" ] && kill $SSHD_PID 2>/dev/null; [ -n "${SRV_PID:-}" ] && kill $SRV_PID 2>/dev/null' EXIT

# --- configuration files ---------------------------------------------------------------
check "sudoers file passes visudo" "visudo -cf config/sensor-ops.sudoers"
sed 's/Cmnd_Alias SENSOR_POWER/Cmnd_Alias sensor_power/' config/sensor-ops.sudoers > "$W/broken.sudoers"
check "a broken sudoers file is caught by visudo" "! visudo -cf $W/broken.sudoers"
check "sudoers grants no shell and no ALL command" "! grep -E '\\bALL\\b *\$|NOPASSWD: *ALL|/bin/(ba)?sh' config/sensor-ops.sudoers"

ssh-keygen -q -t ed25519 -N '' -f "$W/hostkey"
ssh-keygen -q -t ed25519 -N '' -f "$W/ops_key" -C ops@pc
printf 'HostKey %s\nInclude %s\n' "$W/hostkey" "$(pwd)/config/10-sensor-gateway.conf" > "$W/sshd_config"
mkdir -p /run/sshd
check "sshd accepts the SSH configuration (sshd -t)" "/usr/sbin/sshd -t -f $W/sshd_config"
T=$(/usr/sbin/sshd -T -f "$W/sshd_config" -C user=ops,host=pc,addr=192.168.1.20 2>/dev/null)
check "effective SSH settings: no passwords, no root, ssh-users only, 3 tries" \
  "grep -qx 'passwordauthentication no' <<< \"\$T\" && grep -qx 'permitrootlogin no' <<< \"\$T\" && grep -qx 'allowgroups ssh-users' <<< \"\$T\" && grep -qx 'maxauthtries 3' <<< \"\$T\""

sed 's#LAN#192.168.1.0/24#g' config/sensor-gateway.nft > "$W/fw.nft"
if nft -c -f "$W/fw.nft" 2>"$W/nft.err"; then ok "nftables accepts the firewall rules (nft -c)"
elif grep -qi "permitted\|netlink" "$W/nft.err"; then echo "SKIP  nft -c needs CAP_NET_ADMIN here"
else bad "nftables accepts the firewall rules (nft -c)"; cat "$W/nft.err"; fi
check "firewall drops by default and opens only SSH, 5600, 5601 and DHCP" \
  "grep -q 'policy drop' $W/fw.nft && [ \$(grep -cE 'dport (22|5600|5601|68) ' $W/fw.nft) = 4 ]"

# --- harden.sh in a scratch root -------------------------------------------------------------
FR="$W/root"
check "harden.sh refuses to turn passwords off without an SSH key (no lockout)" "! ./harden.sh --root $FR"
check "harden.sh rejects a file that is not a public key" "! ./harden.sh --root $FR --key config/sensor-ops.sudoers"
check "harden.sh rejects a malformed --lan" "! ./harden.sh --root $FR --key $W/ops_key.pub --lan 'any; accept'"
./harden.sh --root "$FR" --key "$W/ops_key.pub" --lan 192.168.1.0/24 > "$W/run1.txt" 2>&1
check "harden.sh writes sudoers (0440), sshd (0644) and firewall (0600) files" \
  "[ \$(stat -c %a $FR/etc/sudoers.d/sensor-ops) = 440 ] && [ \$(stat -c %a $FR/etc/ssh/sshd_config.d/10-sensor-gateway.conf) = 644 ] && [ \$(stat -c %a $FR/etc/nftables.d/sensor-gateway.nft) = 600 ]"
check "the key is installed for ops (.ssh 0700, authorized_keys 0600)" \
  "grep -qF \"\$(cat $W/ops_key.pub)\" $FR/home/ops/.ssh/authorized_keys && [ \$(stat -c %a $FR/home/ops/.ssh) = 700 ] && [ \$(stat -c %a $FR/home/ops/.ssh/authorized_keys) = 600 ]"
check "the firewall file has the LAN filled in" "grep -q 'ip saddr 192.168.1.0/24 tcp dport 22' $FR/etc/nftables.d/sensor-gateway.nft"
./harden.sh --root "$FR" --key "$W/ops_key.pub" --lan 192.168.1.0/24 > "$W/run2.txt" 2>&1
check "running it again changes nothing (idempotent) and adds no duplicate key" \
  "[ \$(grep -c unchanged $W/run2.txt) = 3 ] && [ \$(wc -l < $FR/home/ops/.ssh/authorized_keys) = 1 ]"
check "--tunnel-only closes the logger's ports and keeps SSH" \
  "./harden.sh --root $W/tun --key $W/ops_key.pub --lan 192.168.1.0/24 --tunnel-only && ! grep -q 'dport 560' $W/tun/etc/nftables.d/sensor-gateway.nft && grep -q 'dport 22 ' $W/tun/etc/nftables.d/sensor-gateway.nft"
check "--dry-run writes nothing" "./harden.sh --root $W/dry --key $W/ops_key.pub --dry-run && [ ! -e $W/dry/etc ]"

# --- crypto ---------------------------------------------------------------------------------
K="$W/keys"; ./crypto/make_keys.sh pc "$K" >/dev/null; ./crypto/make_keys.sh pi "$K" >/dev/null
check "private keys are readable by their owner only" "[ \$(stat -c %a $K/pc_private.pem) = 600 ] && [ \$(stat -c %a $K/pi_private.pem) = 600 ]"
head -c 300000 /dev/urandom | od -An -tx1 > "$W/2026-11-05.csv"
./crypto/export_logs.sh "$W/2026-11-05.csv" "$K/pc_public.pem" "$K/pi_private.pem" "$W/exp.tar" >/dev/null
check "export then import gives back the same file" \
  "./crypto/import_logs.sh $W/exp.tar $K/pc_private.pem $K/pi_public.pem $W/in && cmp $W/2026-11-05.csv $W/in/2026-11-05.csv"
check "the export does not contain the log in clear" "! tar -xOf $W/exp.tar | grep -qF \"\$(sed -n 100p $W/2026-11-05.csv)\""
mkdir -p "$W/t" && tar -C "$W/t" -xf "$W/exp.tar"
printf '\x01' | dd of="$W/t/data.enc" bs=1 seek=5000 conv=notrunc status=none
tar -C "$W/t" -cf "$W/tampered.tar" key.enc data.enc sig
check "one changed byte in the data is detected" "! ./crypto/import_logs.sh $W/tampered.tar $K/pc_private.pem $K/pi_public.pem $W/x"
./crypto/make_keys.sh pi "$W/other" >/dev/null
./crypto/export_logs.sh "$W/2026-11-05.csv" "$K/pc_public.pem" "$W/other/pi_private.pem" "$W/forged.tar" >/dev/null
check "an export signed by another device is refused" "! ./crypto/import_logs.sh $W/forged.tar $K/pc_private.pem $K/pi_public.pem $W/x"
check "ECB repeats equal blocks, CBC does not" "./crypto/ecb_vs_cbc.sh"
ssh-keygen -q -t rsa -b 3072 -N '' -f "$W/id_rsa" -C pc
./crypto/ssh_key_to_pem.sh "$W/id_rsa" "$W/conv" >/dev/null
./crypto/export_logs.sh "$W/2026-11-05.csv" "$W/conv/pc_public.pem" "$K/pi_private.pem" "$W/exp2.tar" >/dev/null
check "an ssh-keygen RSA key, converted to PEM, works for the export" \
  "./crypto/import_logs.sh $W/exp2.tar $W/conv/pc_private.pem $K/pi_public.pem $W/in2 && cmp $W/2026-11-05.csv $W/in2/2026-11-05.csv"
check "an Ed25519 SSH key is refused for encryption" "ssh-keygen -q -t ed25519 -N '' -f $W/id_ed && ! ./crypto/ssh_key_to_pem.sh $W/id_ed $W/conv2"

# --- plain TCP vs SSH tunnel, captured --------------------------------------------------------------
if command -v tcpdump >/dev/null && [ "$(id -u)" = 0 ]; then
  SECRET="TEMP=23.4C-SECRET-READING"
  python3 -c "
import socket,sys
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('127.0.0.1',15600)); s.listen(4)
while True:
    c,_=s.accept(); c.recv(100); c.sendall(b'$SECRET\n'); c.close()" & SRV_PID=$!
  id ops >/dev/null 2>&1 || useradd -m ops
  usermod -p '*' ops                                   # as harden.sh does: no password, not locked
  getent group ssh-users >/dev/null || groupadd ssh-users; usermod -aG ssh-users ops
  install -d -m 700 -o ops -g ops /home/ops/.ssh; install -m 600 -o ops -g ops "$W/ops_key.pub" /home/ops/.ssh/authorized_keys
  printf 'Port 2222\nListenAddress 127.0.0.1\nPidFile %s/sshd.pid\n' "$W" >> "$W/sshd_config"
  /usr/sbin/sshd -f "$W/sshd_config" -E "$W/sshd.log"; sleep 1; SSHD_PID=$(cat "$W/sshd.pid" 2>/dev/null)
  tcpdump -i lo -w "$W/cap.pcap" "tcp port 15600 or tcp port 2222" >/dev/null 2>&1 & TD=$!; sleep 1
  printf 'LAST\n' | python3 -c "import socket;s=socket.create_connection(('127.0.0.1',15600));s.sendall(b'LAST\n');print(s.recv(100).decode())" > "$W/direct.txt"
  ssh -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -i "$W/ops_key" -p 2222 -N -L 25600:127.0.0.1:15600 ops@127.0.0.1 & TUN=$!; sleep 2
  python3 -c "import socket;s=socket.create_connection(('127.0.0.1',25600));s.sendall(b'LAST\n');print(s.recv(100).decode())" > "$W/tunnel.txt" 2> "$W/tunnel.err"
  kill $TUN 2>/dev/null; sleep 1; kill $TD; wait $TD 2>/dev/null
  tcpdump -r "$W/cap.pcap" -A "tcp port 2222" 2>/dev/null > "$W/ssh_payload.txt"
  tcpdump -r "$W/cap.pcap" -A "tcp port 15600 and not src host 127.0.0.1 or tcp port 15600" 2>/dev/null > "$W/plain_payload.txt"
  check "SSH: key login works for ops through the tunnel" "grep -q SECRET $W/tunnel.txt"
  check "capture: the reading is visible on the plain TCP connection" "grep -q '$SECRET' $W/plain_payload.txt"
  check "capture: the reading is not visible inside the SSH connection" "! grep -q '$SECRET' $W/ssh_payload.txt && [ -s $W/ssh_payload.txt ]"
  check "SSH: password login is refused" "! ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password -o BatchMode=yes -p 2222 ops@127.0.0.1 true"
  check "SSH: root is refused even with a key" "install -d -m 700 /root/.ssh && cat $W/ops_key.pub >> /root/.ssh/authorized_keys && ! ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -i $W/ops_key -p 2222 root@127.0.0.1 true"
  sed -i "\|$(cut -d' ' -f2 "$W/ops_key.pub")|d" /root/.ssh/authorized_keys
  [ -n "${CAPTURE_DIR:-}" ] && mkdir -p "$CAPTURE_DIR" && cp "$W/cap.pcap" "$CAPTURE_DIR/plain_vs_tunnel.pcap" && chmod 644 "$CAPTURE_DIR/plain_vs_tunnel.pcap"
fi

# --- the real thing (CI virtual machines only) ---------------------------------------------------
if [ "${SYSTEM_TESTS:-0}" = 1 ]; then
  ./harden.sh --key "$W/ops_key.pub" --lan 10.0.0.0/8 --luks 32 > "$W/system.txt" 2>&1 || { cat "$W/system.txt"; bad "harden.sh on this machine"; }
  ./audit.sh > "$W/audit.txt" 2>&1; cat "$W/audit.txt"
  check "audit.sh: everything in place" "grep -q '^0 failed' $W/audit.txt"
fi

echo; echo "$pass passed, $fail failed"
exit $fail
