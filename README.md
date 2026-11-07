# optionfactory-posture

Security posture of optionfactory's developer workstations, for ISO/IEC 27001. One static binary with five commands:

- `report`, on every workstation (hourly systemd timer, as root): runs the checks, queues the report and sends the
  queue to the collector.
- `collect`, on the server: stores the reports of the approved machines, records the unknown ones as pending,
  summarizes the reports after thirty days and, with a Google login, serves the reports as pages to a list of admins.
- `review`, on the server: one line per machine that needs attention, and one per pending machine.
- `pending`, on the server: the pending machines, with the hash of their token.
- `id`, on a workstation: its name and the hash of its token.

The package, with its hourly systemd timer, is in [linux-packages](https://github.com/optionfactory/linux-packages). It
runs only once `/etc/optionfactory-posture/config` exists, setting `POSTURE_COLLECTOR` and `POSTURE_TANG_URL`.

This README describes the tool. How optionfactory runs it (where the collector is, how a machine is approved, when the
review is read) is in the `internal-infra` repository.

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
go out oldest first at the next run; a failed sending is a warning, not a failed run. The agent keeps a report the
collector refuses with 401 (a machine not approved yet) or 5xx, and drops one refused with 400 or 413 (a fault of the
report, which would block the queue forever).

The report describes the machine, never the person using it: no files, sites, applications, sessions or VPN state.

## Machines

The collector and the review read the same list of machines (`machines` in the settings of the collector, `--machines`
or `POSTURE_MACHINES` for the review; default `/etc/optionfactory-posture/machines`), one `<name> <owner> <sha256 of the token>` per line, read again at every
report. The name becomes the directory of the reports of the machine: `[a-z0-9-]` only.

At its first run the agent creates its token, random and readable only by root, in `<state>/token`. The collector
answers 401 to a token not on the list and records the machine as pending in `<reports>/.pending`, with the hostname
and the machine id its report claims. Anyone can send a report under any hostname: what identifies the machine is the
hash of its token, which `pending` and `review` print on the server and `id` prints on the machine itself. Once on the
list, the machine sends its whole queue at its next run; taken off the list, it can no longer send. At most 100
machines wait at a time, and one silent for a month is forgotten.

## Collect

```bash
optionfactory-posture collect [--config /etc/optionfactory-posture/collect.conf]
```

The settings are in a TOML file (mode `0640`, readable by the user of the collector: it holds the secret of the
login); every key is optional except those of `[login]`, and an unknown key stops the collector at start:

```toml
listen = "127.0.0.1:8090"                        # for the reverse proxy, which alone should reach it
trusted_proxy = "172.18.0.10"                    # the proxy: only from it is X-Forwarded-For believed
reports = "/var/lib/optionfactory-posture/reports"
machines = "/etc/optionfactory-posture/machines"

[login]                                          # without it, no pages (see Pages)
client_id = "<google oauth client>"
client_secret = "<its secret>"
public_url = "https://<host>"
admins = "/etc/optionfactory-posture/admins"
domain = "<google workspace domain>"             # optional
```

The collector sits behind a reverse proxy, on an address that only the proxy should reach. With `trusted_proxy`, the
logs of the pages name the client from `X-Forwarded-For` when the proxy sends it; the reports log no address. It
answers `POST /reports` and `GET /favicon.ico`, and the pages below when given a login.

A report is stored only when it carries the token of a machine on the list (`Authorization: Bearer`), the body (at
most 16 KiB) is a report and it is not more than an hour ahead. It goes to
`<reports>/<machine>/<YYYYmmddTHHMMSSZ>.json`, named by the collector after the list and the time: a machine cannot
write reports for another one, nor choose the name. Past 5,000 reports for one machine the collector answers 507 and
the report waits in the queue of the machine. The file keeps the time of the report as its modification time, not the
time it arrived, which would tell when the machine was online. Only rejected reports and new pending machines are
logged, with the machine's name and never the source address. Nothing on the collector can command the machines.

Once a day the collector turns the reports older than thirty days into one summary per day,
`<reports>/<machine>/daily/<YYYYmmdd>.json`: the worst outcome of each check, without times, details or the number of
reports. Summaries are deleted after twelve months, the time between two audits. Thirty days of full reports cover the
review, whose longest margin is a week; the exact times of the reports, which tell when a machine was on, are not kept
longer.

## Pages

With a `[login]` section, a Google OAuth client whose redirect URIs include `<public_url>/oidc/callback`, the collector
also serves:

- `/`: every machine of the list with its owner, the time of its latest report, the outcome of each check and what the
  review would report, then the pending machines with the full hash of their token;
- `/machines/<name>`: the latest report in full, the reports of the last thirty days and the daily summaries.

Only the emails in `admins` (one per line, read again at every request) get in. Sessions last 12 hours and end when the
collector restarts. With `domain` Google offers only the accounts of that Google Workspace domain, and ID tokens of
other domains are refused. Without `[login]` there are no pages and the collector opens no connection.

## Review and pending

```bash
optionfactory-posture review <reports> --machines <list>
optionfactory-posture pending <reports> --machines <list>
```

Both read the directory of the reports, which only the user of the collector can read, and the list of machines;
without `--machines` they read the default list, and fail if it is not there.

`review` covers every machine of the list, with its owner, and each pending one with the first 8 digits of the hash of
its token. A machine is reported when it never sent a report, when its newest report is older than 7 days (past thirty
days, when only the daily summaries are left, the date of the latest summary is reported), or when a check has kept
failing longer than its grace: 2 hours for `firewall`, 48 for `security-updates`, 4 for the rest. Every report is
read, so any that cannot be read is reported, as is one stamped more than an hour ahead. Directories of machines no
longer on the list are skipped.

`pending` prints each pending machine as a line for the list of machines, `<name> <owner> <hash>`, with `<owner>` to
fill in, after a comment with its machine id and when it was first and last heard from.

## Build and release

```bash
make test
make publish-github    # static musl build, GitHub release with SHA256SUMS; then make publish in linux-packages
```
