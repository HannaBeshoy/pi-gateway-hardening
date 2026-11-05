# Lab-day test sheet

About 1.5 hours, on the Raspberry Pi that runs the sensor logger. Do it after the pi-serial-logger lab day, so the logger is running as a service.

## Bring

- Raspberry Pi (3, 4 or 5) with Raspberry Pi OS, power supply, SD card with a **backup image** (in case of a lockout)
- the Arduino sensor node with its USB cable
- a laptop on the same network (the PC), and if possible a second computer or a phone with a terminal app (the "attacker")
- a keyboard and HDMI screen for the Pi, as a fallback if SSH stops working

## 1. Before (10 min)

1. On the PC: `ssh-keygen -t ed25519 -f ~/.ssh/pi_ops`, then copy `~/.ssh/pi_ops.pub` to the Pi.
2. On the Pi: clone this repository, `sudo apt install nftables cryptsetup tcpdump`.
3. Write down which network the Pi is on (`ip -4 addr`), for `--lan`.
4. Run `sudo ./audit.sh` before hardening and keep the output: most lines should FAIL.

## 2. Harden (15 min)

1. `sudo ./harden.sh --dry-run --key ~/pi_ops.pub --lan <network>`: read what it would do.
2. Keep the current SSH session open, then `sudo ./harden.sh --key ~/pi_ops.pub --lan <network> --luks 256`.
3. In a **second** terminal on the PC: `ssh -i ~/.ssh/pi_ops ops@<pi>`. Only close the first session when this works.
4. `sudo ./audit.sh`: all PASS. Save the output to `docs/lab_day/audit_after.txt`.
5. Move the logger's output directory to the encrypted volume (`/var/lib/sensor-logs`), make the service run as user `sensor`, restart it, and check that new lines arrive.

## 3. Attack tests from the second computer (25 min)

Record the command and the result of each in `docs/lab_day/attacks.md`.

| Test | Command | Expected |
| --- | --- | --- |
| password login | `ssh -o PreferredAuthentications=password ops@<pi>` | `Permission denied (publickey)` |
| root login with the right key | add the key to `/root/.ssh/authorized_keys`, `ssh root@<pi>` | refused; remove the key afterwards |
| user not in `ssh-users` | `sudo useradd -m test1`, give it a key, try to log in | refused |
| port scan | `nmap -Pn <pi>` (from a computer on the LAN) | TCP 22 and 5600 open, all else filtered (`nmap -sU -p 5601` for the UDP port) |
| port scan, `--tunnel-only` | re-run harden with `--tunnel-only`, scan again | only 22 |
| SSH rate limit | 15 connection attempts in a loop within a minute | the later ones time out |
| sudo outside the list | as ops: `sudo systemctl restart ssh`, `sudo bash` | `not allowed` |
| sudo inside the list | as ops: `sudo systemctl restart sensor-logger` | works, logged in `/var/log/sudo-sensor-ops.log` |

## 4. Capture on the real network (15 min)

1. On the Pi: `sudo tcpdump -i eth0 -w plain.pcap port 5600` (or `wlan0`), and from the PC `printf 'LAST\n' | nc <pi> 5600`. Stop the capture.
2. Again with the tunnel: `ssh -i ~/.ssh/pi_ops -N -L 5600:localhost:5600 ops@<pi>` on the PC, capture `port 22` to `tunnel.pcap`, and `printf 'LAST\n' | nc localhost 5600` on the PC.
3. Open both in Wireshark (Follow TCP Stream). Save screenshots to `docs/img/`.

## 5. Encrypted volume (15 min)

1. `sudo reboot`; after the reboot check that `/var/lib/sensor-logs` is mounted and the logger writes to it.
2. Passphrase variant: `sudo cryptsetup luksAddKey /var/lib/sensor-logs.luks` (adds a passphrase in a second key slot), then `sudo cryptsetup luksDump /var/lib/sensor-logs.luks`: two key slots. Write down what the drive-encryption lab says about removing the key file slot and what changes at boot.
3. Copy only `sensor-logs.luks` to the PC and try to read it without the key (`strings`, `file`): nothing readable.

## 6. Log export (10 min)

1. `crypto/make_keys.sh pc keys` on the PC, `crypto/make_keys.sh pi keys` on the Pi; swap the public keys with `scp` (over the hardened SSH).
2. On the Pi: `crypto/export_logs.sh /var/lib/sensor-logs/<today>.csv keys/pc_public.pem keys/pi_private.pem today.tar`.
3. Copy `today.tar` to the PC and import it; compare with the Pi's file (`sha256sum` on both).

## Afterwards

- commit `docs/lab_day/` and the screenshots
- tick the lab-day box in the README, change the status line
- update the CV line from "tested on a CI virtual machine" to "tested on the Raspberry Pi"
