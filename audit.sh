#!/usr/bin/env bash
# audit.sh - check that the hardening is in place on this machine; prints PASS / FAIL per item.
#   sudo ./audit.sh
fails=0
check() { if eval "$2" >/dev/null 2>&1; then echo "PASS  $1"; else echo "FAIL  $1"; fails=$((fails + 1)); fi; }
T=$(sshd -T 2>/dev/null)
check "SSH: password login off"            "grep -qx 'passwordauthentication no' <<< \"\$T\""
check "SSH: root login off"                "grep -qx 'permitrootlogin no' <<< \"\$T\""
check "SSH: only group ssh-users"          "grep -qx 'allowgroups ssh-users' <<< \"\$T\""
check "SSH: at most 3 tries"               "grep -qx 'maxauthtries 3' <<< \"\$T\""
check "sudo: file valid"                   "visudo -cf /etc/sudoers.d/sensor-ops"
check "sudo: ops may restart the logger"   "sudo -l -U ops | grep -q 'restart sensor-logger'"
check "sudo: ops may not run a shell"      "! sudo -l -U ops | grep -qE '\(ALL\) ALL|/bin/(ba)?sh'"
check "user sensor cannot log in"          "getent passwd sensor | grep -q nologin"
check "ops has no usable password"         "[ \"\$(getent shadow ops | cut -d: -f2)\" = '*' ]"
check "firewall: input policy drop"        "nft list chain inet sensor_gateway input | grep -q 'policy drop'"
check "logs: directory 0750, owner sensor" "[ \"\$(stat -c '%a %U' /var/lib/sensor-logs)\" = '750 sensor' ]"
if [ -f /var/lib/sensor-logs.luks ]; then
  check "logs: on an open LUKS volume"     "cryptsetup status sensor-logs | grep -q 'type:.*LUKS'"
  check "logs: key readable by root only"  "[ \"\$(stat -c '%a %U' /root/sensor-logs.key)\" = '600 root' ]"
fi
echo "$fails failed"
exit $fails
