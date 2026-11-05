# Pi Gateway Hardening

[![CI](https://github.com/HannaBeshoy/pi-gateway-hardening/actions/workflows/ci.yml/badge.svg)](https://github.com/HannaBeshoy/pi-gateway-hardening/actions/workflows/ci.yml)

**IT Security course project** · University of Debrecen, Faculty of Informatics · Bash, OpenSSH, sudo, nftables, LUKS, OpenSSL · **tested on Linux and on a CI virtual machine; Raspberry Pi test on the December lab day**

The Raspberry Pi that runs the [sensor logger](https://github.com/HannaBeshoy/pi-serial-logger) sits on a network and keeps a record of every reading. This project secures it with the tools of the IT Security labs, one script per job, each one checked by an automatic test:

- [x] `harden.sh`: users and groups, a `sudoers` rule that allows only the logger's commands, SSH with keys only, an nftables firewall that drops by default, an encrypted LUKS volume for the logs, file permissions. Safe to run twice, `--dry-run` to preview, and it refuses to turn passwords off before a key is installed, so it cannot lock you out
- [x] `audit.sh`: checks every setting on the running machine and prints PASS or FAIL
- [x] `crypto/`: log export from the Pi to the PC with AES-256-CBC, the key wrapped with RSA-OAEP, and an Ed25519 signature by the Pi; works with the PC's existing `ssh-keygen` RSA key; ECB vs CBC demonstration
- [x] An SSH tunnel to the logger's port, with a packet capture that shows the reading in clear on plain TCP and hidden inside SSH
- [x] **29 tests pass**, and CI hardens a real Ubuntu virtual machine (firewall and LUKS volume included) and audits it: **all 13 `audit.sh` checks PASS**
- [ ] Lab day: on the Raspberry Pi, with an attack test from a second computer ([test sheet](docs/LAB_DAY.md))

## What it protects against

| Threat | Protection | Course lab |
| --- | --- | --- |
| password guessing over SSH | keys only, no root, only group `ssh-users`, 3 tries, at most 10 new connections a minute | SSH, SSH key authentication |
| an operator account used for more than it needs | `sudo` allows exactly 7 commands (the logger service and shutdown), no shell | users, sudo and sudoers |
| the logger process taken over | it runs as `sensor`, a system user with no login and no shell | users |
| other devices on the network reaching services | nftables: drop by default; SSH, the logger's ports and DHCP from the local network only | (firewall) |
| readings read on the network | SSH tunnel to the logger (`--tunnel-only` closes the plain ports) | SSH, Wireshark |
| the SD card stolen | logs on a LUKS2-encrypted volume | drive encryption 1 and 2 |
| a log file read or changed on the way to the PC | AES-256-CBC + RSA-OAEP key wrap + Ed25519 signature | OpenSSL enc, rsautl, key transformation |

## Results

**Plain TCP vs SSH tunnel.** The test asks the logger's port for the last reading twice, once directly and once through `ssh -L`, and records both with `tcpdump`. On the plain connection the reading is in the packet:

```text
127.0.0.1.15600 > 127.0.0.1.50744: Flags [P.], length 26
....TEMP=23.4C-SECRET-READING
```

On the SSH connection (port 2222 in the test) the only readable text is the version banner, `SSH-2.0-OpenSSH_9.6p1`; the 42 packets after it are encrypted and the reading is not found in them. The capture is in [`docs/captures/plain_vs_tunnel.pcap`](docs/captures/plain_vs_tunnel.pcap) for Wireshark.

**Log export.** A 920 KB log is exported and imported back byte for byte. One changed byte in the encrypted data, or an export signed by a different Pi, is refused before anything is decrypted.

**ECB vs CBC.** Six equal 16-byte blocks (a log repeats the same line often) give 1 distinct ciphertext block in ECB mode and 6 in CBC: ECB shows the pattern, which is why the export uses CBC.

**Lockout protection.** Without a key for `ops`, `harden.sh` stops before writing the SSH configuration.

## Running it

Tests (needs root for the SSH and capture part; everything else runs in a scratch directory):

```bash
sudo apt install openssh-server nftables cryptsetup tcpdump
sudo bash tests/run_tests.sh
sudo CAPTURE_DIR=/tmp/cap bash tests/run_tests.sh      # also keep the capture
```

On the Raspberry Pi (Raspberry Pi OS or Debian):

```bash
ssh-keygen -t ed25519 -f ~/.ssh/pi_ops        # on the PC
scp ~/.ssh/pi_ops.pub pi@raspberrypi.local:    # copy the public key to the Pi
sudo ./harden.sh --dry-run --key ~/pi_ops.pub --lan 192.168.1.0/24          # see what it would do
sudo ./harden.sh --key ~/pi_ops.pub --lan 192.168.1.0/24 --luks 256         # do it
sudo ./audit.sh
ssh -i ~/.ssh/pi_ops -L 5600:localhost:5600 ops@raspberrypi.local           # from the PC: tunnel
```

Log export: `crypto/make_keys.sh pc keys/` on the PC (or `crypto/ssh_key_to_pem.sh ~/.ssh/id_rsa keys/` to use an existing RSA key), `crypto/make_keys.sh pi keys/` on the Pi, swap the public keys, then `crypto/export_logs.sh` on the Pi and `crypto/import_logs.sh` on the PC.

## Repository layout

```text
harden.sh                 the hardening, six steps
audit.sh                  checks the result on the running machine
config/                   sshd drop-in, sudoers rule, nftables rules (installed by harden.sh)
crypto/                   key pairs, log export and import, SSH key conversion, ECB vs CBC
tests/run_tests.sh        29 tests; SYSTEM_TESTS=1 also hardens and audits the machine (CI only)
docs/                     project guide, lab-day test sheet, the packet capture
```

The [project guide](docs/PROJECT_GUIDE.md) explains every decision and links it to the course labs.

## Status

Verified on Linux and on a CI virtual machine (GitHub Actions hardens an Ubuntu VM, including the firewall and a LUKS volume, and runs `audit.sh`). On the lab day: the same on the Raspberry Pi, and the attack test from a second computer.

Part of a Raspberry Pi sensor gateway: [pi-serial-logger](https://github.com/HannaBeshoy/pi-serial-logger) (System Programming) collects the data, this project secures the Pi, and pi-aws-pipeline (AWS Cloud) sends the data to the cloud.

## Author

Beshoy Hanna · Computer Science Engineering BSc, University of Debrecen · [LinkedIn](https://www.linkedin.com/in/beshoy-hanna-8b52213a0)
