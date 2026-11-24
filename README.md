# optionfactory-posture

**Posture measures the machine, not the work done on it.** It checks how the machine is set up (the disk encrypted, the
firewall on, the updates installed, the screen locking) and never what anyone does with it: no files, documents, sites,
applications or messages. The only trace of use is that each report shows the machine was on at that hour.

Security posture of optionfactory's developer workstations, for ISO/IEC 27001. One static binary with six commands:

- `report`, on every workstation (hourly systemd timer, as root): runs the checks, queues the report and sends the
  queue to the collector.
- `collect`, on the server: stores the reports of the approved machines, records the unknown ones as pending,
  summarizes the reports after thirty days and, with a Google login, serves the reports as pages to a list of admins
  and, for their own machines, to the owners.
- `review`, on the server: one line per machine that needs attention, and one per pending machine.
- `mail`, on the server (daily systemd timer): the review by mail to the admins, and to each owner the reminder of their
  own machines.
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
| `os` | Linux Mint 22.x, Ubuntu 24.04 or 26.04, Debian 13 |
| `reboot-pending` | no `/var/run/reboot-required`, or younger than 7 days |
| `security-updates` | `apt-get -s dist-upgrade` installs nothing from a security suite (the detail names at most 10 packages) |
| `automatic-updates` | `unattended-upgrades` is installed and `apt-config dump` turns on `APT::Periodic::Update-Package-Lists` and `APT::Periodic::Unattended-Upgrade` |
| `baseline` | the installed `optionfactory-workstation` or `optionfactory-laptop` is the version `apt-cache policy` would install (the detail names both): `unattended-upgrades` silently skips an upgrade that brings a package from an origin it does not allow yet |
| `firewall` | ufw active, incoming denied or rejected by default |
| `docker-ports` | no container port published on every interface (`0.0.0.0`, `::`): Docker bypasses ufw there. Only the mappings are reported, not the containers |
| `sshd` | `sshd -T`: no password or keyboard-interactive login, no root, a `TrustedUserCAKeys` |
| `empty-passwords` | no account in `/etc/shadow` has an empty password (the detail tells how many, never the names) |
| `apparmor` | AppArmor is enabled, with at least one profile in enforce mode |
| `journal` | journald storage is persistent |
| `clock-sync` | `timedatectl` says the clock is synchronized (`NTPSynchronized=yes`), by any NTP client |
| `screen-lock` | the system dconf defaults enable the lock after at most 15 minutes, and lock both keys (Cinnamon or GNOME) |
| `auto-login` | neither LightDM (`autologin-user`, `autologin-guest`), GDM (`AutomaticLoginEnable`, `TimedLoginEnable`) nor SDDM (`[Autologin] User`) logs anyone in by itself (the detail names the file, never the user) |

A check that cannot run (missing command, not root, a command still running after a minute, then killed) is `unknown`
and counts as failing.

## Report

```bash
optionfactory-posture report --print --tang-url http://tang.office.opfa.net    # prints the report, sends nothing
```

`--collector` (HTTPS only), `--tang-url` and `--state` (default `/var/lib/optionfactory-posture`, with the token of
the machine and the queue of the reports not sent yet) also come from `POSTURE_COLLECTOR`, `POSTURE_TANG_URL` and
`POSTURE_STATE`. Reports wait in the queue while the collector is unreachable or the machine is not approved yet, and
go out oldest first at the next run; a failed sending is a warning, not a failed run. The agent keeps a report the
collector refuses with 401 (a machine not approved yet) or 5xx, and drops one refused with 400 or 413 (a fault of the
report, which would block the queue forever). It follows no redirect: only a 2xx answer takes a report out of the
queue. The queue is readable only by root (directory 0700, reports 0600), and reports older than thirty days, which the
collector would refuse, are dropped from it.

The report describes the machine, never the person using it: no files, sites, applications, sessions or VPN state.
Besides the checks it carries the hardware, without serial numbers: manufacturer, model, board and BIOS from the
firmware (`/sys/class/dmi/id`); CPU, threads and microcode, and what the kernel says of each known CPU flaw; memory; the
graphics cards with their driver and memory (`amdgpu` in sysfs, `nvidia-smi` for `nvidia`); the network cards (not the
virtual interfaces) with their driver, their own MAC address (`ip -json link` when Wi-Fi shows a random one) and whether
they are wireless. Models are named from `pci.ids` and `usb.ids`. It also lists the TCP ports listening on the network
(`/proc/net/tcp` and `tcp6`, not those on loopback): the address and the port, never the process.

## Machines

The collector and the review read the same list of machines (`machines` in the settings of the collector, `--machines`
or `POSTURE_MACHINES` for the review; default `/etc/optionfactory-posture/machines`), one `<name> <owner> <sha256 of the token>` per line, read again at every
report. The name becomes the directory of the reports of the machine: `[a-z0-9-]` only. A list with two lines sharing a name or
a token is refused as a whole (reports answered 500, pages and review failing) until it is fixed; owners are read in
lower case.

At its first run the agent creates its token, random and readable only by root, in `<state>/token`. The collector
answers 401 to a token not on the list and records the machine as pending in `<reports>/.pending`, with the hostname
and the machine id its report claims, kept only when they are a hostname (letters, digits, dots and dashes) and a hex
id, `invalid` otherwise. Anyone can send a report under any hostname: what identifies the machine is the hash of its
token, which `pending` and `review` print on the server and `id` prints on the machine itself. Once on the list, the
machine sends its whole queue at its next run; taken off the list, it can no longer send. At most 20 machines wait at
a time; once a day the collector forgets the ones approved since and those silent for a month.

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

[mail]                                           # read only by `mail` (see Review, reminders and pending)
relay = "smtp-relay.gmail.com"                   # STARTTLS, no credentials: the relay accepts the address of the server
port = 587                                       # optional, 587 by default
from = "posture-noreply@<domain>"
admins = "admins@<domain>"
```

The collector sits behind a reverse proxy, on an address that only the proxy should reach. With `trusted_proxy`, the
logs of the pages name the client from `X-Forwarded-For` when the proxy sends it; the reports log no address. It
answers `POST /reports` and `GET /favicon.ico`, and the pages below when given a login.

A report is stored only when it carries the token of a machine on the list (`Authorization: Bearer`), the body (at
most 16 KiB) is a report with at most 64 checks named in `[a-z0-9-]`, and it is not more than an hour ahead nor older
than thirty days (the agent drops it, as it would have been summarized at once). A daily summary keeps at most 64
checks. It goes to
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

- `/`: every machine of the list with its owner, its type, the time of its latest report and one line per finding (the
  check, for how long, its detail), then the checks still within their grace; for each check, how many machines pass,
  fail or cannot run it and which do not pass; the pending machines with the full hash of their token. The summary
  cards lead to the machines they count (`?show=attention`, `?show=passing`);
- `/people` and `/people/<owner>`: the owners with their machines and what needs attention on each, and the machines of
  one owner;
- `/types` and `/types/<laptop|workstation|unknown>`: the machines by type, from the SMBIOS chassis type of their latest
  report (`unknown`: no report, an agent that does not send it yet, or a chassis that is neither, such as a virtual
  machine), with the checks most failed on each type;
- `/checks` and `/checks/<name>`: every check with what it verifies and the machines not passing it; for one check, those
  machines with how long and why, longest first, what to do, and the machines passing it;
- `/machines/<name>`: what needs attention and what to do, the latest report in full (the checks not passing first),
  the hardware, the listening ports, the reports of the last thirty days and the daily summaries.

The emails in `admins` (one per line, read again at every request) read every page. The owners of the machines on the
list read only `/` and `/people/<owner>`, both with their own machines, and `/machines/<name>` of those machines; the
other pages, and the machines of others, are not found for them. Sessions last 12 hours and end when the
collector restarts. With `domain` Google offers only the accounts of that Google Workspace domain, and ID tokens of
other domains are refused. Without `[login]` there are no pages and the collector opens no connection.

## Review, reminders and pending

```bash
optionfactory-posture review <reports> --machines <list>
optionfactory-posture review <reports> --machines <list> --html [--pages-url https://<host>]
optionfactory-posture review <reports> --machines <list> --owner <email> [--html [--pages-url https://<host>]]
optionfactory-posture mail [--config /etc/optionfactory-posture/collect.conf]
optionfactory-posture pending <reports> --machines <list>
```

Both read the directory of the reports, which only the user of the collector can read, and the list of machines;
without `--machines` they read the default list, and fail if it is not there.

`review` covers every machine of the list, with its owner, and each pending one with the first 8 digits of the hash of
its token. A machine is reported when it never sent a report, when its newest report is older than 7 days (past thirty
days, when only the daily summaries are left, the date of the latest summary is reported), or when a check has kept
failing longer than its grace: 2 hours for `firewall`, 24 for `clock-sync`, 48 for `security-updates` and `baseline`, 4
for the rest. Every report is read, so any that cannot be read is reported, as is one stamped more than an hour ahead.
Directories of machines no longer on the list are skipped. With `--html` it prints the same as the body of a mail
(inline styles, the light palette of the pages), linking each machine to its page when given `--pages-url`, and prints
nothing when nothing needs attention. What machines send (hostnames, details) is escaped in the HTML, and kept on its line in the text: control characters
become spaces. A check failing because it
could not run (`unknown`) is reported as `could not run` rather than `failing`.

With `--owner`, the reminder for one person: only the machines of that owner (case does not matter), each finding
followed by what to do about it (the command to run, or to ask IT), without the pending machines and the unreadable
reports, which only the admins can deal with. The HTML links to the page of the owner, which they can open with their
own Google login. It prints nothing when their machines are in order.

`mail`, meant for a daily timer, reads the settings of the collector: the reports, the list of machines, the public
address of the pages from `[login]` and the relay from `[mail]`. When something needs attention it mails the review,
text and HTML, to `admins`, then to each owner of a machine needing attention their reminder, from `from`. The relay
must offer STARTTLS, checked against the public roots built into the binary, and is greeted with the domain of `from`;
there are no credentials. When the review cannot be made (the list of machines unreadable, say), the admins get the
error instead. A reminder that cannot be sent does not stop the others; the command then fails, naming whom it missed.

`pending` prints each pending machine as a line for the list of machines, `<name> <owner> <hash>`, with `<owner>` to
fill in, after a comment with its machine id and when it was first and last heard from.

## Build and release

```bash
make test
make publish-github    # static musl build, GitHub release with SHA256SUMS; then make publish in linux-packages
```
