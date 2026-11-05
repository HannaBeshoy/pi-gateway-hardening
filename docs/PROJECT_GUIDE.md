# Project guide

Every step of `harden.sh` and every script in `crypto/` comes from one of the IT Security labs. This guide gives the reason for each decision, the lab it comes from, and how the test checks it. Read it next to the code.

| Lab (course material) | Where it is used |
| --- | --- |
| Managing users (`users.pdf`) | step 1: users `sensor` and `ops`, groups `ssh-users` and `sensor-ops` |
| sudo and sudoers (`sudoers_en.pdf`) | step 2: `config/sensor-ops.sudoers` |
| SSH, SSH key authentication (`ssh_en.pdf`, `ssh-key-auth_en.pdf`) | step 3: `config/10-sensor-gateway.conf`, the tunnel |
| Wireshark and dumpcap (`wireshark.pdf`) | the plain vs tunnel capture |
| Drive encryption 1 and 2 (`encrypt-loop.pdf`, `encrypted-device.pdf`) | step 5: the LUKS volume |
| OpenSSL: DES and AES (`enc_en.pdf`) | `crypto/export_logs.sh`, `crypto/ecb_vs_cbc.sh` |
| OpenSSL: RSA encrypt and decrypt (`rsautl-encrypt-decrypt_en.pdf`) | the key wrap in the export |
| Key transformation (`key-transform_en.pdf`) | `crypto/ssh_key_to_pem.sh` |

## 1. Users: least privilege

Two accounts with different jobs:

- `sensor` runs the logger. It is a **system user** (`useradd --system`) with the shell `/usr/sbin/nologin` and a locked password: nobody can log in as it. If the logger had a bug that let an attacker run code, they would get only this account, which owns the log directory and nothing else.
- `ops` is the person who maintains the Pi. It is in two groups: `ssh-users` (may log in over SSH) and `sensor-ops` (may manage the logger with sudo).

Groups instead of user names in the rules: a second operator is added with one `usermod -aG`, no configuration file changes.

**Locked vs no password.** `useradd` leaves the password field as `!`, which means *locked*, and OpenSSH refuses a locked account even with a correct key (the test found this). `harden.sh` sets it to `*`: no password can ever match, but the account is not locked, so key login works. `audit.sh` checks for exactly `*`.

## 2. sudo: name every command

`config/sensor-ops.sudoers`:

```text
Cmnd_Alias SENSOR_SERVICE = /usr/bin/systemctl status sensor-logger, ... restart ..., stop, start, journalctl -u sensor-logger
Cmnd_Alias SENSOR_POWER   = /usr/sbin/shutdown -h now, /usr/sbin/shutdown -r now
%sensor-ops ALL=(root) NOPASSWD: SENSOR_SERVICE, SENSOR_POWER
```

The lab's task (a user who may only shut the computer down) extended to the logger. Each command is written with its arguments, so `systemctl restart sensor-logger` is allowed but `systemctl restart ssh` is not. Commands that could open a shell are never listed (an editor, `less`, `find`, `systemctl edit`, any interpreter): through them, one allowed command becomes every command. `NOPASSWD` because `ops` has no password; the protection is the SSH key plus the short list. Every use is logged to `/var/log/sudo-sensor-ops.log`.

The file is checked with `visudo -cf` before it is installed: a syntax error in a sudoers file can disable sudo for everyone. The test also feeds `visudo` a broken copy to make sure the check catches it.

## 3. SSH: keys only

`config/10-sensor-gateway.conf` is a drop-in in `/etc/ssh/sshd_config.d/`, so the distribution's own file stays untouched.

| Setting | Why |
| --- | --- |
| `PasswordAuthentication no`, `KbdInteractiveAuthentication no` | a guessed or stolen password is not enough; a key cannot be guessed |
| `PermitRootLogin no` | log in as `ops`, then sudo; every action is tied to a person |
| `AllowGroups ssh-users` | an account added later by some package cannot log in by accident |
| `MaxAuthTries 3`, `LoginGraceTime 30` | slows down an attacker trying many keys |
| `AllowTcpForwarding local` | the tunnel to the logger needs it; remote forwarding (exposing the PC's ports to the Pi) is off |
| `X11Forwarding no`, `AllowAgentForwarding no` | features the gateway does not need |

**No lockout.** Turning passwords off before a key is installed would lock the operator out of a Pi with no screen. `harden.sh` installs the key first (`--key`), checks that `authorized_keys` is not empty, checks the new configuration with `sshd -t`, and only then reloads `sshd`; the existing session stays open. The test runs it without a key and checks that it stops.

**The tunnel.** The logger's TCP port (5600) speaks plain text. `ssh -L 5600:localhost:5600 ops@pi` makes the PC's port 5600 lead, through the encrypted SSH connection, to the Pi's own port 5600. With `--tunnel-only` the firewall closes 5600 and 5601 to the network altogether, and the tunnel is the only way in.

## 4. The capture: seeing the difference

The Wireshark lab, done with `tcpdump` (the same capture library, and it runs in a script). The test starts a stand-in for the logger that answers `LAST` with a recognisable reading, then:

1. asks it directly: the reading is in the TCP payload, readable by anyone who can capture on the network;
2. asks it through an SSH tunnel: the capture on the SSH port shows the version banners (`SSH-2.0-OpenSSH_9.6p1`), then only encrypted packets. The reading is searched for in every packet and not found.

Open `docs/captures/plain_vs_tunnel.pcap` in Wireshark and use *Follow TCP Stream* on each connection. (Both ends are on one machine in the test, so the capture also shows the tunnel's last step from `sshd` to the port on the Pi itself, in clear; on a real network that step never leaves the Pi.)

## 5. Firewall: drop by default

`config/sensor-gateway.nft`, an nftables table of its own (it does not touch other rules):

```text
policy drop
ct state established,related accept      replies to connections the Pi started (updates, DNS, the cloud upload)
iif "lo" accept                          the Pi talking to itself (the tunnel ends here)
ip saddr LAN tcp dport 22 ... limit rate 10/minute accept
ip saddr LAN tcp dport 5600 accept       (removed by --tunnel-only)
ip saddr LAN udp dport 5601 accept       (removed by --tunnel-only)
udp dport 68 accept                      DHCP
```

Only what the gateway is for is allowed, and only from the local network (`--lan`, checked against a strict pattern so it cannot inject a rule). Rule files are checked with `nft -c` before they are loaded.

## 6. LUKS: the SD card can be stolen

A Pi is small and easy to take. The two drive-encryption labs encrypt a device with `cryptsetup`; here the encrypted container is a file (`/var/lib/sensor-logs.luks`), because a Pi usually has one SD card and repartitioning it is risky. The steps are the lab's: `luksFormat` (LUKS2), `open`, `mkfs.ext4`, `mount`, plus `/etc/crypttab` and `/etc/fstab` entries so it opens at boot.

The honest limit: the key file is in `/root` on the same card, so the volume opens automatically and a thief with the whole card can open it too. What it does protect: the logs when the volume image is copied or backed up alone, and wiping (destroy the key and the data is gone). For full protection the key must come from somewhere else at boot (typed in, or a USB key kept separately); the lab day tests the typed passphrase variant.

## 7. Log export: confidentiality, integrity, origin

`crypto/export_logs.sh` on the Pi, `crypto/import_logs.sh` on the PC. It combines three labs:

1. **AES-256-CBC** encrypts the file with a fresh random key and IV each time (`enc` lab). AES is fast for files of any size.
2. **RSA-OAEP** with the PC's public key encrypts the AES key, the IV, the file's SHA-256 and its name (`rsautl` lab, with `pkeyutl` and OAEP padding instead of the old PKCS#1 v1.5). RSA alone can only encrypt a few hundred bytes; AES alone would need a shared secret on the Pi.
3. **Ed25519 signature** by the Pi over both encrypted parts. Anyone can encrypt to the PC's public key, so encryption alone does not prove where a file came from; only this Pi has its signing key.

The import checks the signature **first** and decrypts only if it is valid, then compares the SHA-256. The tests change one byte of the encrypted data and sign an export with a different Pi's key: both are refused.

**Why CBC and not ECB** (`crypto/ecb_vs_cbc.sh`): the DES lab encrypts identical blocks and sees identical ciphertext in ECB mode. A sensor log repeats the same line all the time, so ECB would show its structure. CBC mixes each block with the previous ciphertext: six equal blocks give six different ones.

**Using the PC's SSH key** (`crypto/ssh_key_to_pem.sh`): the key-transformation lab converts an `ssh-keygen` key to the PEM format OpenSSL reads (`ssh-keygen -e -m pkcs8` for the public key, `-p -m PEM` then `openssl pkcs8 -topk8` for a copy of the private key). The script refuses Ed25519 keys, which can sign but not encrypt.

## 8. audit.sh

Hardening that is not checked drifts: a package update replaces a file, someone adds a rule by hand. `audit.sh` reads the *effective* settings (`sshd -T`, `sudo -l -U ops`, `nft list`, `stat`, `cryptsetup status`) rather than the files, and prints PASS or FAIL for each. It can run from a timer and its exit status is the number of failures.

## Tests

`tests/run_tests.sh` has three parts:

- **Configuration and crypto** (no changes to the machine): `visudo`, `sshd -t`, `sshd -T`, `nft -c`, `harden.sh` in a scratch root (file modes, the key, idempotence, dry run, bad input, lockout protection, `--tunnel-only`), and the crypto scripts.
- **SSH and capture** (root): a second `sshd` on port 2222 with the project's configuration; key login, password refused, root refused even with a key, and the capture.
- **System** (`SYSTEM_TESTS=1`, CI only): hardens the machine for real, including the firewall and a 32 MB LUKS volume, then runs `audit.sh`. GitHub Actions does this on a fresh Ubuntu virtual machine on every push.

## Notes for the three tracks

- **Embedded systems.** The same steps make any Linux device on a network presentable: a gateway, a test bench PC, an industrial edge box. The no-lockout rule matters most on devices without a screen.
- **FPGA to semiconductors.** A board that boots Linux (Zynq, an SoC) has the same attack surface; secure boot and a hardware key store would replace the key file on the card.
- **Product security.** This is the exercise in miniature: list the threats, match each one with a control, check the controls automatically, and state the limits (the LUKS key on the same card) instead of hiding them.

## Possible extensions

- `fail2ban` or nftables sets to block an address after failed logins
- an `audit.sh` run every day from a systemd timer, with the result sent to the cloud pipeline
- the LUKS key from a USB stick that is removed after boot
