# Security

## Reporting a vulnerability

Report it privately through GitHub: **Security → Report a vulnerability** on this repository. Do not open a public
issue. Only the latest release is supported; fixes go into a new release.

## Threat model

### The agent: `optionfactory-posture report`

**The report is the machine's own account of itself, not proof.** The agent runs as root on the workstation it
checks, so whoever has root there (developers have `sudo`) can stop it, change it or forge its reports. It catches
drift and forgotten settings, not a user who wants to deceive; the controls that a local administrator cannot
falsify (VPN login, SSH certificates, the logs of the central services) live elsewhere.

Within that scope it keeps its exposure small:

- **Read-only**: it reads the state of the machine and changes nothing. The commands it runs (`lsblk`,
  `cryptsetup luksDump`, `clevis luks list`, `apt-get -s`, `ufw status`, `sshd -T`, `systemd-analyze cat-config`,
  `dconf read`, `docker ps`) are executed directly with fixed arguments, never through a shell, with `LC_ALL=C`.
- **Nothing listens**: the agent opens no port and accepts no input from the network; it only sends. Nothing on the
  collector can command a machine.
- **The machine, not the person**: a report holds the hostname, the machine id, the system, the kernel and the
  outcome of each check. No files, sites, applications, sessions or VPN state; `docker-ports` reports only the
  published port mappings, not the containers. The time of each report does tell that the machine was on then (see
  Retention).
- **Only to the collector**: reports wait in `/var/lib/optionfactory-posture/queue`, readable only by root, and go
  out when the collector is reachable again, with the machine's token (`/var/lib/optionfactory-posture/token`,
  created at the first run, readable only by root). The agent sends only over HTTPS, checking the certificate against the public roots built into the
  binary: on any network, a spoofed DNS answer for the collector's name cannot make it send the reports or the token
  elsewhere.

### The collector: `optionfactory-posture collect`

**A machine is its token, once an admin approves it.** The collector is public, so that machines report from anywhere
without the VPN. Each machine creates its own random token at its first run; the collector knows only the SHA-256 of
the tokens, from the list of machines, and refuses with 401 a report without a known one. Approving is the step that
matters: an unknown token is recorded as pending under the hostname its report claims, which anyone can choose, so the
admin compares the hash with the one the machine prints (`optionfactory-posture id`) before putting it on the list.
Whoever takes a token can write reports under that machine's name, as whoever has root on it already can; taking the
line off the list revokes it.
The collector listens behind nginx on an address not reachable from outside the server (on the instance, the host's
address on the network of the containers: the other containers reach it too, nothing outside the instance does) and
runs as an unprivileged user. It answers `POST /reports` and `GET /favicon.ico`, a fixed file built into the binary,
and, when given a Google login, the pages of the reports (see below); nothing else.

Within that scope:

- **One directory per machine, chosen by the collector**: the name comes from the list, not from the report, so a
  machine cannot write reports for another one, nor choose a file name: the name comes from the time of the report.
- **Only reports reach the disk**: the body (at most 16 KiB) is parsed as a report and written again; anything else
  is refused. Reports more than an hour ahead are refused.
- **Bounded per machine**: past 5,000 reports for one machine the collector refuses more (507), and the reports
  wait in the machine's queue.
- **Bounded pending machines**: a pending machine is a hostname, a machine id and two dates, never its reports. At most
  100 wait at a time, past that new ones are not recorded, and one silent for a month is forgotten.
- **No addresses**: the source address of a report is often an employee's home. Neither nginx nor the collector logs
  it: only refused reports are logged, with the machine's name, and a pending machine once, with its hostname. Each stored file keeps the time of
  the report as its modification time, not the time it arrived, which would tell when the machine was online.

### The pages of the reports

Optional: without a `[login]` section the collector serves no pages and opens no connection. With it, the reports are
readable in a browser by the emails on the list of admins (`admins`), and the collector connects to Google to sign
them in:

- **Google signs in, the list decides**: the authorization code flow with PKCE and a state bound to a short cookie. The
  code goes back to Google over HTTPS, checked against the public roots built into the binary, and the ID token it
  returns is checked for issuer, audience, expiry, a verified email and, with `domain`, its `hd` claim. The email must be on the list, read again at
  every request, so taking someone off the list closes their session at once.
- **Sessions**: a cookie with the email and the expiry (12 hours), signed with a key made at start and kept only in
  memory: a restart signs everyone out. `HttpOnly`, `Secure`, `SameSite=Lax`.
- **Read-only**: the pages only read the reports and the list of machines; nothing in them changes either, approves a
  machine or reaches a workstation.
- **Everything from a report is text**: hostnames, details and every other field are escaped, and the pages carry a
  Content-Security-Policy without scripts, so a report or a pending machine with markup in it cannot run anything in
  the admin's browser.
- **The secret**: the client secret is only in the settings file, readable by the collector and root, never in the
  arguments, which other users of the machine can read.

### Retention

Full reports stay 30 days, long enough for the review; then each day of a machine becomes one summary (the worst
outcome of each check, without times or details), deleted after twelve months. Reports are personal data about
employees' machines (Statuto dei lavoratori, art. 4, and the GDPR): the agent is meant to be activated only after the
employees have been told what it collects and why.

### The review: `optionfactory-posture review`

It reads the stored reports and the list of machines and prints findings. It opens no network
connection and writes nothing. Every report is parsed as data; one that cannot be parsed is itself a finding.

## Build and supply chain

A single static binary (musl), released on GitHub with `SHA256SUMS`, and packaged in the signed APT repository
[linux-packages](https://github.com/optionfactory/linux-packages). The dependencies are few: `ureq` with rustls for
sending and for the login, `ring` for the hashes and the signed sessions, `axum` and `tokio` for the collector, `serde`,
`base64`, `jiff` and `clap`.
