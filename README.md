# optionfactory-posture

Security posture of optionfactory's developer workstations, for ISO/IEC 27001. One static binary with five commands:

- `optionfactory-posture report`, on every workstation (hourly systemd timer, as root): runs the checks, queues the
  report and sends the queue to the collector.
- `optionfactory-posture collect`, on the instance: stores the reports and summarizes them after thirty days.
- `optionfactory-posture review`, on the instance: reads the collected reports and prints one line per machine that
  needs attention, and one per machine waiting for approval.
- `optionfactory-posture pending`, on the instance: prints the machines waiting for approval, as entries for the list.
- `optionfactory-posture id`, on a workstation: prints its name and the hash of its token, to compare before approving.

The package, with its hourly systemd timer, is in [linux-packages](https://github.com/optionfactory/linux-packages). It
runs only once `/etc/optionfactory-posture/config` exists, setting `POSTURE_COLLECTOR` and `POSTURE_TANG_URL`;
optionfactory's internal `optionfactory-workstation` package provides it. The deployment of the collector and the
alarm is in `internal-services`.

Threat model, data protection and how to report a vulnerability: [SECURITY.md](SECURITY.md).

## Checks

| Check | Passes when |
| --- | --- |
| `disk-encryption` | on every fixed disk (not USB, not removable) anything with a signature (filesystem, swap, LVM, RAID) is LUKS2 or sits on it; only the EFI system partition and `/boot` may stay in the clear |
| `disk-recovery-keyslot` | every LUKS2 device has a keyslot not used by Clevis (the recovery passphrase) |
| `disk-tang` | `clevis luks list` shows, on every LUKS2 device, a `tang` binding to `--tang-url` |
| `os` | Linux Mint 22.x, Ubuntu 24.04 or Debian 13 |
| `reboot-pending` | no `/var/run/reboot-required`, or younger than 7 days |
| `security-updates` | `apt-get -s dist-upgrade` installs nothing from a security suite (the detail names at most 10 packages) |
| `firewall` | ufw active, incoming denied or rejected by default |
| `docker-ports` | no container port published on every interface (`0.0.0.0`, `::`): Docker bypasses ufw there. Only the mappings are reported, not the containers |
| `sshd` | `sshd -T`: no password or keyboard-interactive login, no root, a `TrustedUserCAKeys` |
| `journal` | journald storage is persistent |
| `screen-lock` | the system dconf defaults enable the lock after at most 15 minutes, and lock both keys (Cinnamon or GNOME) |

A check that cannot run (missing command, not root) is `unknown` and counts as failing.

## Report

```bash
optionfactory-posture report --print --tang-url http://tang.office.opfa.net    # prints the report, sends nothing
```

`--collector` (HTTPS only), `--tang-url` and `--state` (default `/var/lib/optionfactory-posture`, with the token of
the machine and the queue of the reports not sent yet) also come from `POSTURE_COLLECTOR`, `POSTURE_TANG_URL` and
`POSTURE_STATE`. Reports wait in the queue while the collector is unreachable or the machine is not approved yet, and
go out oldest first at the next run; a failed sending is a warning, not a failed run.

The report describes the machine, never the person using it: no files, sites, applications, sessions or VPN state.

## Approving a machine

At its first run the agent creates its token, random and readable only by root, in `<state>/token`. The collector
answers 401 to a token it does not know and records the machine as pending, with its hostname and machine id; the
review then reports it, and on the instance

```bash
optionfactory-posture pending /var/lib/optionfactory-posture/reports
```

prints it as an entry for the list of machines that the collector and the review read (`--machines`,
`POSTURE_MACHINES`, default `/etc/optionfactory-posture/machines`, one `<name> <owner> <sha256 of the token>` per
line). Anyone can send a report under any hostname: before approving, compare the hash with the one the machine itself
prints,

```bash
sudo optionfactory-posture id
```

then add the owner and put the entry on the list. At its next run the machine sends its whole queue. A machine taken
off the list can no longer send. At most 100 machines wait at a time, and one silent for a month is forgotten.

## Collect

```bash
optionfactory-posture collect --listen /run/optionfactory-posture/collect.sock --reports /var/lib/optionfactory-posture/reports
```

`--listen`, `--reports` and `--machines` also come from `POSTURE_LISTEN`, `POSTURE_REPORTS` and `POSTURE_MACHINES`.
The collector sits behind nginx on a Unix socket in a directory only nginx can reach. A report is stored only when it
carries the token of a machine on the list (`Authorization: Bearer`, 401 otherwise; the list is read again at every
report; an unknown one makes the machine pending), the body (at most 16 KiB) is a report and it is not more than an hour ahead. It goes to
`<reports>/<machine>/<YYYYmmddTHHMMSSZ>.json`, named by the collector after the list and the time: a machine cannot
write reports for another one, nor choose the name. Past 5,000 reports for one machine the collector answers 507 and
the report waits in the queue of the machine. The file keeps the time of the report as its modification time, not the
time it arrived, which would tell when the machine was online. Only rejected reports are logged, with the machine's
name and never the source address. Nothing on the collector can command the machines.

The agent keeps a report the collector refuses with 401 (a machine not on the list yet) or 5xx, and drops one refused
with 400 or 413 (a fault of the report, which would block the queue forever). Once a day the collector turns the reports
older than thirty days into one summary per day, `<reports>/<machine>/daily/<YYYYmmdd>.json`: the worst outcome of each check,
without times, details or the number of reports. Summaries are deleted after twelve months, the time between two audits.
Thirty days of full reports cover the review, whose longest margin is a week; the exact times of the reports, which tell
when a machine was on, are not kept longer.

## Review

```bash
optionfactory-posture review /var/lib/optionfactory-posture/reports
```

Every machine of the list is reviewed, with its owner, and each pending one is reported with the first 8 digits of the
hash of its token. A machine is reported when it never sent a report, when its
newest report is older than 7 days
(past thirty days, when only the daily summaries are left, the date of the latest summary is reported), or when a check
has kept failing longer than its grace: 2 hours for `firewall`, 48 for `security-updates`, 4 for the rest. Every
report is read, so any that cannot be read is reported, as is one stamped more than an hour ahead. Directories of
machines no longer on the list are skipped.

## Build and release

```bash
make test
make publish-github    # static musl build, GitHub release with SHA256SUMS; then make publish in linux-packages
```
