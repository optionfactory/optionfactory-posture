# Security

## Reporting a vulnerability

Report it privately through GitHub: **Security → Report a vulnerability** on this repository. Do not open a public
issue. Only the latest release is supported; fixes go into a new release.

## What it is, and what it is not

**Posture measures the machine, not the work done on it.** It checks how a workstation is set up (the disk encrypted,
the firewall on, the updates installed, the screen locking) and never what anyone does with it: no files, documents,
sites, applications or messages. The only trace of use is that each report shows the machine was on at that hour.

**A report is the machine's own account of itself, not proof.** The agent runs as root on the workstation it checks, so
whoever has root there (developers have `sudo`) can stop it, change it or forge its reports. It catches drift and
forgotten settings, not a user who wants to deceive; the controls that a local administrator cannot falsify (VPN
login, SSH certificates, the logs of the central services) live elsewhere.

## Who can do what

| Who | Can | Cannot, or only within these bounds |
| --- | --- | --- |
| Anyone on the internet | send `POST /reports` and open the login of the pages | store a report: a token not on the list gets 401 and at most a pending entry (a hostname and a hex machine id, `invalid` otherwise; 20 at most; listed to the admins). Read a page: Google login and the lists decide |
| An approved machine: whoever has root on it, or its token | write reports under its own name, true or false | write for another machine (the directory comes from the list), choose a file name, or go past the bounds: 16 KiB, 64 checks named in `[a-z0-9-]`, not more than an hour ahead nor older than thirty days, about 5,000 reports, 64 checks in a daily summary. What it sends is escaped in HTML and kept on its line in text, so it cannot write findings for another machine |
| An owner, signed in | read the pages of their own machines: findings, the latest report with its hardware, ports and details, thirty days of report times, the daily summaries | read the machines of others (the same "not found" as a missing one), the people, types and checks pages, the pending machines, the server paths of unreadable reports |
| An admin, signed in | read every page: every machine, every owner, the pending ones. The report times tell when each machine was on, for thirty days | change anything: the pages only read. Page views are not logged |
| Whoever edits the list of machines | decide which tokens are accepted and who owns each machine, so who reads which pages | |
| Whoever edits the list of admins, or `[mail].admins` | decide who reads every page, and who gets the daily review; the two lists are set apart | |
| The collector, or whoever controls it | read every report; drop reports (a 2xx, a 400 or a 413 takes a report out of the agent's queue) | command a machine: the agent reads only the status of the answer, never its body, and follows no redirect |
| The reverse proxy | see in clear what TLS protects: the tokens, the session cookies, the reports | (it is trusted: only from it is `X-Forwarded-For` believed, and only for the logs of the pages) |
| The other services on the same host | reach the collector directly, in plain HTTP, without the proxy's rate limit | send more than 16 KiB a report, which the collector itself refuses |
| Google, as the identity provider | sign in whoever controls a Google account whose verified email is on the lists; with `domain`, only accounts of that Workspace | |
| The SMTP relay, and the mailboxes | read every review and reminder; mails stay past the retention of the reports | |
| A public certificate authority | issue a certificate that the binary accepts: it trusts the public roots built into it, without pinning, for the collector (from the agent), for Google's token endpoint (from the login) and for the relay (from `mail`). With control of the collector's outbound path, a certificate for Google's token endpoint would sign in as any email on the lists, since the ID token comes straight from it and its signature is not checked | |
| Root and the collector's user on the server | read every report and the settings file, with the client secret of the login. The collector creates its files with the default permissions: only a private directory of the reports (0700, as optionfactory's deployment makes it) keeps other users of the server out | |

## The agent: `optionfactory-posture report`

- **Read-only**: it reads the state of the machine and changes nothing. The commands it runs (`lsblk`,
  `cryptsetup luksDump`, `clevis luks list`, `apt-get -s`, `apt-cache policy`, `apt-config dump`, `ufw status`,
  `sshd -T`, `systemd-analyze cat-config`, `dconf read`, `docker ps`, `timedatectl show`, `ip -json link`, and
  `nvidia-smi` when there is an NVIDIA card) are executed directly, never through a shell, with `LC_ALL=C`, stdin
  closed and fixed arguments, apart from the device paths that `lsblk` lists. A command still running after a minute
  is killed and its check is `unknown`, with the command's error output as its detail.
- **Nothing listens**: the agent opens no port and accepts no input from the network; it only sends. Nothing on the
  collector can command a machine: the agent reads only the status of the answer and follows no redirect. A 2xx takes
  a report out of its queue, as do a 400 and a 413 (a report the collector will never take, which would block the
  queue); any other answer keeps it.
- **The machine, not the work done on it**: a report holds the version of the agent, the hostname, the machine id, the
  system, the kernel, the chassis type (laptop or desktop), the outcome of each check with its detail, the hardware and
  the listening ports.
  The hardware, without serial numbers: models, sizes, firmware and microcode versions, the CPU flaws the kernel
  reports, and the network cards built into the machine with their MAC address (also the real one when Wi-Fi shows a
  random one; not USB ones, such as a tethered phone). The ports: each TCP port listening on the network and whether on
  every address or on one; never the address, which would tell the networks the machine is on, nor the process. The
  details name up to 10 pending security updates by package, and the disks by device path (for an LVM or encrypted
  volume, a name chosen on the machine); of the mount points they name only the system ones (`/`, `/home`, `/boot`,
  ...): any other is `elsewhere`, as it may hold a user name or a volume label. `disk-tang` carries the output of
  `clevis luks list`, `docker-ports` only the published port mappings, `empty-passwords` only a count, `auto-login` only
  the file, and a check that cannot run the error output of its command. No files, sites, applications, sessions or VPN
  state.
- **Only to the collector**: reports wait in `/var/lib/optionfactory-posture/queue` (0700, reports 0600, whatever
  starts the agent) and go out when the collector is reachable again, with the machine's token
  (`/var/lib/optionfactory-posture/token`, created at the first run, 0600). Reports older than thirty days, which the
  collector would refuse, are dropped from the queue. The agent sends only over HTTPS, checking the certificate against
  the public roots built into the binary: on any network, a spoofed DNS answer for the collector's name cannot make it
  send the reports or the token elsewhere.

## The collector: `optionfactory-posture collect`

**A machine is its token, once an admin approves it.** The collector is public, so that machines report from anywhere
without the VPN. Each machine creates its own random token at its first run; the collector knows only the SHA-256 of
the tokens, from the list of machines, and refuses with 401 a report without a known one. Approving is the step that
matters: the admin takes the hash from what the machine itself prints (`optionfactory-posture id`), since anyone can
send a report under any hostname. Whoever takes a token can write reports under that machine's name, as whoever has
root on it already can; taking the line off the list revokes it. A list where two lines share a name or a token is
refused as a whole.

The collector listens behind a reverse proxy on an address meant to be reachable only from the server, and runs as an
unprivileged user. It answers `POST /reports` and `GET /favicon.ico`, a fixed file built into the binary, and, when
given a Google login, the pages and the login routes (see below); nothing else.

- **One directory per machine, chosen by the collector**: the name comes from the list, not from the report, so a
  machine cannot write reports for another one, nor choose a file name: the name comes from the time of the report.
- **Bounded reports**: the body (at most 16 KiB) is parsed as a report and written again; anything else is refused. A
  report has at most 64 checks named in `[a-z0-9-]`, is not more than an hour ahead nor older than thirty days. Past
  5,000 reports for one machine the collector refuses more (507), and they wait in the machine's queue. A daily
  summary keeps at most 64 checks.
- **Bounded pending machines**: a pending machine is a hostname and a machine id (kept only when they are a hostname
  and a hex id, `invalid` otherwise) and two dates, never its reports. At most 20 wait at a time; past that new ones
  are not recorded, which does not stop anyone from being approved. Once a day the collector forgets those approved
  since and those silent for a month. The bound is counted before writing, without a lock, so requests at the same
  moment can pass it by a few; the same holds for the 5,000 reports.
- **No address of a report**: the source address of a report is often an employee's home. The collector never logs
  it, and the proxy should not either (in optionfactory's deployment, nginx keeps neither an access log nor an error
  log for the collector). Each stored file keeps the time of the report as its modification time, not the time it
  arrived, which would tell when the machine was online; the file system still records the arrival in the file's
  change time and the directory's modification time, which nothing in the tool shows. Reports from agents before 0.9.0
  carry the addresses the ports listen on: the collector keeps only the ports.
- **What it logs**: reports refused, with the machine's name and the reason; every report without a valid token (only
  the proxy's rate limit bounds how many); a new pending machine once, with its cleaned hostname; a failed login, with
  the email and the client address (from the proxy's `X-Forwarded-For`); errors reading the lists, rendering a page,
  storing and retention, with paths. Where the log goes is the deployment's choice.

## The pages and the login

Optional: without a `[login]` section the collector serves no pages and opens no connection. With it, the admins (the
emails in `admins`) read every page, the owner of a machine on the list of machines reads that machine's pages, and the
collector connects to Google to sign them in.

- **Google signs in, the lists decide**: the authorization code flow with PKCE and a state bound to a short cookie. The
  code goes back to Google over HTTPS, checked against the public roots built into the binary, with the client secret,
  and the ID token it returns is checked for issuer, audience, expiry, a verified email and, with `domain`, its `hd`
  claim. The email must be on the list of admins or own a machine on the list of machines, both read again at every
  request, so taking someone off the list, or their last machine, closes their session at once. Owners are compared
  in lower case.
- **What an owner sees**: `/` and `/people/<owner>` with their own machines, and `/machines/<name>` of those. The other
  pages (`/people`, `/types`, `/checks`), the machines of others and the pending machines are "not found" for them, the
  same as a name not on the list. Findings only the admins can deal with, an unreadable report and its path on the
  server, are left out.
- **Sessions**: a cookie with the email and the expiry (12 hours), signed with a key made at start and kept only in
  memory: a restart signs everyone out. `__Host-` prefix, `HttpOnly`, `Secure`, `SameSite=Lax`. Signing out clears the
  cookie in that browser; a copy of the cookie stays valid until it expires or the collector restarts.
- **Without a session**: `/login`, `/oidc/callback` (which sends the code to Google with the client secret),
  `/logout`, `/posture.css` and `/favicon.ico`.
- **Read-only**: the pages only read the reports and the lists; nothing in them changes either, approves a machine or
  reaches a workstation.
- **Everything from a report is text**: hostnames, check names, details and every other field are escaped, and the
  pages carry a Content-Security-Policy without scripts or inline styles (only the collector's own stylesheet), with
  `base-uri` and `form-action` closed, and `X-Content-Type-Options: nosniff`, so a report or a pending machine with
  markup in it cannot run anything in the reader's browser.
- **The secret**: the client secret is only in the settings file, readable by the collector's user and root, never in
  the arguments, which other users of the machine can read. `mail` reads the same file.

## The review: `optionfactory-posture review` and `mail`

`review` reads the stored reports and the lists and prints findings. It opens no network connection and writes
nothing. Every report is parsed as data; one that cannot be parsed is itself a finding. In its text, what a machine
sent stays on its line: control characters, line separators and direction marks become spaces.

`mail` sends the same review, text and HTML, to `[mail].admins`, and to each owner only the findings about their own
machines: never those of others, the pending machines or the paths of unreadable reports. It writes nothing and
connects only to the relay of `[mail]`, over STARTTLS checked against the public roots built into the binary, and
refuses to go on in clear text. It has no SMTP credentials: the relay trusts the address of the server. The HTML of the
mails escapes what machines send, as the pages do, and pending machines appear with their cleaned hostname and the
first 8 digits of their hash. Meant for a daily timer, it can run as the collector's user (in optionfactory's
deployment it does, with the same hardening).

## Retention

Full reports stay 30 days on the collector, long enough for the review; then each day of a machine becomes one summary
(the worst outcome of each check, without times or details), deleted after twelve months. On a workstation, queued
reports are dropped after thirty days. Copies outside the collector follow their own retention: the backups of the
server, and the mails already delivered. Reports are personal data about employees' machines (Statuto dei
lavoratori, art. 4, and the GDPR): the agent is meant to be activated only after the employees have been told what it
collects and why.

## Known limits

- Whoever has root on a workstation decides what its reports say.
- The reverse proxy sees tokens, session cookies and reports in clear, and the binary trusts any public certificate
  authority for the names it connects to; the ID token of the login is trusted for coming straight from Google, not
  for its signature.
- Identity is the verified email Google gives, not Google's stable account id.
- A copied session cookie stays valid until it expires or the collector restarts.
- Anyone can fill the 20 pending places, after which new machines are not listed as pending; they are still approved
  from the hash `optionfactory-posture id` prints.
- An admin sees, for thirty days, when each machine was on.

## Build and supply chain

A single static binary (musl), released on GitHub with `SHA256SUMS`, and packaged in the signed APT repository
[linux-packages](https://github.com/optionfactory/linux-packages). The dependencies are few: `ureq` with rustls for
sending and for the login, `lettre` with rustls for the mails, `ring` for the hashes and the signed sessions, `axum`
and `tokio` for the collector, `serde`, `serde_json` and `toml` for the reports and the settings, `base64`, `jiff` and
`clap`.
