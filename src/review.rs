use crate::machines::{self, Machine, Pending};
use crate::report::{Report, Status};
use crate::web::pages::escape;
use crate::web::url_encode;
use jiff::{SignedDuration, Timestamp};
use std::collections::BTreeMap;
use std::fmt::{self, Write};
use std::path::{Path, PathBuf};

/// Laptops off the VPN, on holiday or switched off keep their reports queued: a week of silence is the limit.
const LONGEST_SILENCE: SignedDuration = SignedDuration::from_hours(7 * 24);

/// How long a check may keep failing before it is reported.
fn grace(check: &str) -> SignedDuration {
    match check {
        // turned off for development
        "firewall" => SignedDuration::from_hours(2),
        // unattended-upgrades runs once a day
        "security-updates" | "baseline" => SignedDuration::from_hours(48),
        // offline, the kernel stops calling the clock synchronized after some hours
        "clock-sync" => SignedDuration::from_hours(24),
        _ => SignedDuration::from_hours(4),
    }
}

/// What needs attention about a machine. Displayed, the lines of the review and of the mails.
#[derive(Clone, Debug, PartialEq)]
pub enum Finding {
    /// A check not passing in the latest report since `since`; `Status::Unknown` when it could not run.
    Check {
        name: String,
        status: Status,
        since: Timestamp,
        detail: String,
    },
    /// No report since then: the newest one, or the day of the newest summary once the reports are gone.
    Silent {
        since: Timestamp,
    },
    Never,
    /// A report stamped more than an hour ahead: a clock that far ahead hides the reports that follow.
    Future {
        at: Timestamp,
    },
    Unreadable {
        path: PathBuf,
        error: String,
    },
}

/// One line each, in the terminal and in the text of the mails: what a machine sent cannot start a line of its own, nor
/// send the terminal escape sequences.
impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // also the line separators and the direction marks, which would move or hide the rest of the line
        let invisible = |c: char| {
            c.is_control()
                || matches!(c, '\u{2028}' | '\u{2029}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        };
        let line = |text: &str| -> String { text.chars().map(|c| if invisible(c) { ' ' } else { c }).collect() };
        match self {
            Finding::Check {
                name,
                status: Status::Unknown,
                since,
                detail,
            } => write!(f, "{} could not run since {since}: {}", line(name), line(detail)),
            Finding::Check {
                name, since, detail, ..
            } => write!(f, "{} failing since {since}: {}", line(name), line(detail)),
            Finding::Silent { since } => write!(f, "no report since {since}"),
            Finding::Never => write!(f, "never reported"),
            Finding::Future { at } => write!(f, "report from the future: {at}"),
            Finding::Unreadable { path, error } => {
                write!(f, "unreadable report {}: {}", path.display(), line(error))
            }
        }
    }
}

impl Finding {
    /// What the owner of the machine can do about it.
    pub fn remedy(&self) -> Option<&'static str> {
        match self {
            Finding::Check {
                status: Status::Unknown,
                ..
            } => Some("the check could not run: ask IT"),
            Finding::Check { name, .. } => remedy(name),
            Finding::Silent { .. } | Finding::Never => {
                Some("switch the machine on and connect it to the network; if it is on, ask IT")
            }
            Finding::Future { .. } => Some("sudo timedatectl set-ntp true"),
            Finding::Unreadable { .. } => None,
        }
    }

    /// Whether the owner can act on it: an unreadable report is a matter for the admins.
    pub fn for_owner(&self) -> bool {
        !matches!(self, Finding::Unreadable { .. })
    }
}

/// What the owner of a machine can do about a failing check, in the words of the table of the checks in internal-infra
/// (`docs/posture.md`); what needs IT says so.
pub fn remedy(check: &str) -> Option<&'static str> {
    Some(match check {
        "disk-encryption" => "ask IT: the machine needs encrypting",
        "disk-recovery-keyslot" | "disk-tang" | "apparmor" => "ask IT",
        "os" => "upgrade the system, with IT",
        "reboot-pending" => "reboot",
        "security-updates" | "baseline" => "sudo apt update && sudo apt full-upgrade",
        "automatic-updates" | "journal" | "screen-lock" => "reinstall the baseline",
        "firewall" => "sudo ufw enable",
        "docker-ports" => "publish the container ports on 127.0.0.1 only",
        "sshd" => "undo your changes to /etc/ssh/sshd_config",
        "empty-passwords" => "sudo passwd <user>",
        "clock-sync" => "sudo timedatectl set-ntp true",
        "auto-login" => "turn off automatic login in the login settings",
        _ => return None,
    })
}

/// The reports of a machine are in `<reports>/<name>/`, the directory the collector chose from the token the report
/// carried: the machine cannot write under another one's name. The list tells whose machine it is, and which machines
/// should be reporting at all.
///
/// With `owner`, the reminder of that person; with `html`, the same as a mail body, linking to the pages at
/// `pages_url` when given. Nothing when nothing needs attention.
pub fn review(
    reports: &Path,
    machines: &[Machine],
    owner: Option<&str>,
    html: bool,
    pages_url: Option<&str>,
) -> Result<(), String> {
    let mut review = Review::read(reports, machines, Timestamp::now())?;
    if let Some(owner) = owner {
        review = review.of_owner(owner);
    }
    match (review.is_empty(), html) {
        (true, _) => {}
        (false, true) => print!("{}", review.html(pages_url)),
        (false, false) => print!("{}", review.text()),
    }
    Ok(())
}

/// What needs attention: the machines with findings, and the machines waiting for approval. Read once, then narrowed
/// to each owner for their reminder.
pub struct Review<'a> {
    attention: Vec<(&'a Machine, Vec<Finding>)>,
    pending: Vec<(String, Pending, Timestamp)>,
    /// The person a reminder is for; `None` for the review of the admins.
    owner: Option<String>,
    now: Timestamp,
}

impl<'a> Review<'a> {
    pub fn read(reports: &Path, machines: &'a [Machine], now: Timestamp) -> Result<Review<'a>, String> {
        Ok(Review {
            attention: machines
                .iter()
                .map(|machine| (machine, reviewed(reports, machine, now).findings))
                .filter(|(_, findings)| !findings.is_empty())
                .collect(),
            pending: machines::pending(reports, machines)?,
            owner: None,
            now,
        })
    }

    /// The reminder of `owner` (case does not matter): their machines only, without the pending machines and the
    /// unreadable reports, which only the admins can deal with.
    pub fn of_owner(&self, owner: &str) -> Review<'a> {
        Review {
            attention: self
                .attention
                .iter()
                .filter(|(machine, _)| machine.owner.eq_ignore_ascii_case(owner))
                .map(|(machine, findings)| {
                    let findings: Vec<Finding> =
                        findings.iter().filter(|finding| finding.for_owner()).cloned().collect();
                    (*machine, findings)
                })
                .filter(|(_, findings)| !findings.is_empty())
                .collect(),
            pending: Vec::new(),
            owner: Some(owner.to_ascii_lowercase()),
            now: self.now,
        }
    }

    /// The owners of the machines needing attention, once each whatever the case of their address.
    pub fn owners(&self) -> Vec<String> {
        let mut owners: Vec<String> = self
            .attention
            .iter()
            .map(|(machine, _)| machine.owner.to_ascii_lowercase())
            .collect();
        owners.sort();
        owners.dedup();
        owners
    }

    pub fn is_empty(&self) -> bool {
        self.attention.is_empty() && self.pending.is_empty()
    }

    /// The findings and the pending machines: what the subject of a mail counts.
    pub fn count(&self) -> usize {
        self.attention.iter().map(|(_, findings)| findings.len()).sum::<usize>() + self.pending.len()
    }

    /// One line per finding and per pending machine; in a reminder, what to do indented under each finding.
    pub fn text(&self) -> String {
        let mut text = String::new();
        for (machine, findings) in &self.attention {
            for finding in findings {
                match &self.owner {
                    Some(_) => {
                        let _ = writeln!(text, "{}: {finding}", machine.name);
                        if let Some(remedy) = finding.remedy() {
                            let _ = writeln!(text, "  to do: {remedy}");
                        }
                    }
                    None => {
                        let _ = writeln!(text, "{} ({}): {finding}", machine.name, machine.owner);
                    }
                }
            }
        }
        for (hash, pending, _) in &self.pending {
            let _ = writeln!(
                text,
                "{}: waiting for approval since {}, token {}",
                pending.hostname,
                pending.first_seen,
                &hash[..8]
            );
        }
        text
    }

    /// The page of the owner of a reminder, or the pages themselves for the admins.
    pub fn link(&self, pages_url: &str) -> String {
        let url = pages_url.trim_end_matches('/');
        match &self.owner {
            Some(owner) => format!("{url}/people/{}", url_encode(owner)),
            None => url.to_string(),
        }
    }
}

const FONT: &str = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
const MUTED: &str = "#475569";
const BORDER: &str = "#cbd5e1";
const PRIMARY: &str = "#0369a1";
const DANGER: &str = "#b91c1c";
const WARNING: &str = "#b45309";

impl Review<'_> {
    /// Tables and inline styles, the light palette of the pages: mail clients drop stylesheets and most of CSS.
    pub fn html(&self, pages_url: Option<&str>) -> String {
        let (attention, pending, owner, now) = (&self.attention, &self.pending, self.owner.as_deref(), self.now);
        let pages_url = pages_url.map(|url| escape(url.trim_end_matches('/')));
        let mut summary = Vec::new();
        match (attention.len(), owner) {
            (0, _) => {}
            (1, None) => summary.push("1 machine needs attention".to_string()),
            (n, None) => summary.push(format!("{n} machines need attention")),
            (1, Some(_)) => summary.push("1 of your machines needs attention".to_string()),
            (n, Some(_)) => summary.push(format!("{n} of your machines need attention")),
        }
        if !pending.is_empty() {
            summary.push(format!("{} waiting for approval", pending.len()));
        }
        let mut html = format!(
            "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta name=\"color-scheme\" content=\"light\"><title>Posture review</title></head>\n\
         <body style=\"margin:0;padding:0;background:#f1f5f9;\">\n\
         <table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"background:#f1f5f9;\">\
         <tr><td align=\"center\" style=\"padding:28px 12px;\">\n\
         <table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" \
         style=\"max-width:640px;font-family:{FONT};color:#0f172a;\">\n\
         <tr><td style=\"padding:0 4px 4px;font-size:22px;font-weight:700;\">Posture\
         <span style=\"font-weight:400;color:{MUTED};\"> / {}</span></td></tr>\n\
         <tr><td style=\"padding:0 4px 22px;font-size:15px;color:{MUTED};\">{}.</td></tr>\n",
            now.strftime("%Y-%m-%d"),
            summary.join(", ")
        );
        if owner.is_some() {
            let _ = writeln!(
                html,
                "<tr><td style=\"padding:0 4px 18px;font-size:14px;color:{MUTED};\">A daily reminder from the posture \
             checks of the company machines: it stops once your machines are back in order.</td></tr>"
            );
        }
        for (machine, findings) in attention {
            let name = match &pages_url {
                Some(url) => format!(
                    "<a href=\"{url}/machines/{0}\" style=\"color:{PRIMARY};text-decoration:none;\">{0}</a>",
                    escape(&machine.name)
                ),
                None => escape(&machine.name),
            };
            let _ = write!(
                html,
                "<tr><td style=\"padding:0 0 12px;\">\
             <table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" \
             style=\"background:#ffffff;border:1px solid {BORDER};border-left:4px solid {DANGER};border-radius:8px;\">\
             <tr><td style=\"padding:14px 18px;\">\n\
             <div style=\"font-size:17px;font-weight:600;\">{name}\
             <span style=\"font-size:13px;font-weight:400;color:{MUTED};\">&nbsp;&nbsp;{}</span></div>\n\
             <ul style=\"margin:8px 0 0;padding-left:20px;font-size:14px;line-height:1.55;\">\n",
                if owner.is_some() {
                    String::new()
                } else {
                    escape(&machine.owner)
                }
            );
            for finding in findings {
                let remedy = match (owner, finding.remedy()) {
                    (Some(_), Some(remedy)) => format!(
                        "<div style=\"margin:2px 0 6px;font-size:13px;color:{MUTED};\">To do: {}</div>",
                        escape(remedy)
                    ),
                    _ => String::new(),
                };
                let _ = writeln!(html, "<li>{}{remedy}</li>", escape(&finding.to_string()));
            }
            html.push_str("</ul></td></tr></table></td></tr>\n");
        }
        if !pending.is_empty() {
            let _ = write!(
                html,
                "<tr><td style=\"padding:14px 4px 4px;font-size:17px;font-weight:600;\">Waiting for approval</td></tr>\n\
             <tr><td style=\"padding:0 4px 10px;font-size:13px;color:{MUTED};\">Anyone can send a report under any \
             hostname: before approving, the hash must match what <code>optionfactory-posture id</code> prints on the \
             machine itself.</td></tr>\n\
             <tr><td style=\"padding:0 0 12px;\">\
             <table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" \
             style=\"background:#ffffff;border:1px solid {BORDER};border-left:4px solid {WARNING};border-radius:8px;\
             font-size:14px;\">\n"
            );
            for (hash, machine, last_seen) in pending {
                let _ = writeln!(
                    html,
                    "<tr><td style=\"padding:10px 18px;border-bottom:1px solid #e2e8f0;\">\
                 <div style=\"font-weight:600;\">{}</div>\
                 <div style=\"font-size:13px;color:{MUTED};\">first seen {}, last seen {}, token \
                 <code style=\"color:#0f172a;\">{}</code></div></td></tr>",
                    escape(&machine.hostname),
                    machine.first_seen.strftime("%Y-%m-%d %H:%M"),
                    last_seen.strftime("%Y-%m-%d %H:%M"),
                    escape(&hash[..8])
                );
            }
            html.push_str("</table></td></tr>\n");
        }
        if let Some(url) = &pages_url {
            let (href, label) = match owner {
                Some(owner) => (format!("{url}/people/{}", url_encode(owner)), "Open your machines"),
                None => (url.clone(), "Open the posture pages"),
            };
            let _ = writeln!(
                html,
                "<tr><td style=\"padding:14px 4px 0;\"><a href=\"{href}\" style=\"display:inline-block;padding:9px 18px;\
             background:{PRIMARY};color:#ffffff;border-radius:6px;font-size:14px;font-weight:600;\
             text-decoration:none;\">{label}</a></td></tr>"
            );
        }
        let _ = write!(
            html,
            "<tr><td style=\"padding:18px 4px 0;font-size:12px;color:{MUTED};\">Times are UTC.</td></tr>\n\
         </table></td></tr></table>\n</body></html>\n"
        );
        html
    }
}

/// A machine as the review sees it.
pub struct Reviewed {
    /// Newest first.
    pub reports: Vec<Report>,
    pub findings: Vec<Finding>,
    /// Checks not passing in the latest report, still within their grace: not findings yet.
    pub within_grace: Vec<Finding>,
}

/// The reports of a machine and what needs attention about it.
pub fn reviewed(reports: &Path, machine: &Machine, now: Timestamp) -> Reviewed {
    let dir = reports.join(&machine.name);
    let mut names: Vec<_> = std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .filter(|path| {
            !path
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with('.'))
        })
        .collect();
    names.sort_by(|a, b| b.cmp(a));
    let has_reports = !names.is_empty();
    // all of them, a month at most, so that any unreadable one is reported
    let mut unreadable = Vec::new();
    let newest_first: Vec<Report> = names
        .into_iter()
        .filter_map(|path| {
            let report = std::fs::read(&path).map_err(|e| e.to_string());
            match report.and_then(|bytes| serde_json::from_slice::<Report>(&bytes).map_err(|e| e.to_string())) {
                Ok(report) => Some(report),
                Err(error) => {
                    unreadable.push(Finding::Unreadable { path, error });
                    None
                }
            }
        })
        .collect();
    let (mut findings, within_grace) = findings(newest_first.iter(), now);
    findings.extend(unreadable);
    // reports go after thirty days, summaries after a year: a machine silent that long is told by its summaries
    let latest_summary = std::fs::read_dir(dir.join("daily"))
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".json") && !name.starts_with('.'))
        .max();
    // summaries are named after their day, `YYYYmmdd.json`
    let summarized = latest_summary
        .and_then(|day| jiff::civil::Date::strptime("%Y%m%d", day.trim_end_matches(".json")).ok())
        .and_then(|day| day.to_zoned_datetime(jiff::tz::TimeZone::UTC).ok())
        .map(|day| day.timestamp());
    match (has_reports, summarized) {
        (true, _) => {}
        (false, Some(since)) => findings.push(Finding::Silent { since }),
        (false, None) => findings.push(Finding::Never),
    }
    Reviewed {
        reports: newest_first,
        findings,
        within_grace,
    }
}

/// The findings, and the checks still within their grace. Reads back only as far as needed to find when each failing
/// check last passed.
fn findings<'a>(mut newest_first: impl Iterator<Item = &'a Report>, now: Timestamp) -> (Vec<Finding>, Vec<Finding>) {
    let Some(latest) = newest_first.next() else {
        return (Vec::new(), Vec::new());
    };
    let mut findings = Vec::new();
    let mut within_grace = Vec::new();
    // a clock far ahead keeps this report the newest, hiding the ones that follow
    if latest.taken_at.duration_since(now) > SignedDuration::from_hours(1) {
        findings.push(Finding::Future { at: latest.taken_at });
    }
    if now.duration_since(latest.taken_at) > LONGEST_SILENCE {
        findings.push(Finding::Silent { since: latest.taken_at });
    }
    let mut failing: BTreeMap<String, (Timestamp, String, Status)> = latest
        .checks
        .iter()
        .filter(|check| check.status != Status::Pass)
        .map(|check| {
            (
                check.name.clone(),
                (latest.taken_at, check.detail.clone(), check.status),
            )
        })
        .collect();
    let mut open: Vec<String> = failing.keys().cloned().collect();
    for older in newest_first {
        if open.is_empty() {
            break;
        }
        open.retain(|name| {
            let still_failing = older
                .checks
                .iter()
                .any(|check| &check.name == name && check.status != Status::Pass);
            if still_failing {
                failing.get_mut(name).expect("open checks are failing").0 = older.taken_at;
            }
            still_failing
        });
    }
    for (name, (since, detail, status)) in failing {
        let due = now.duration_since(since) >= grace(&name);
        // the status as the latest report has it: a check that could not run needs IT, not the owner
        let finding = Finding::Check {
            name,
            status,
            since,
            detail,
        };
        match due {
            true => findings.push(finding),
            false => within_grace.push(finding),
        }
    }
    (findings, within_grace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Check;

    fn report(at: &str, firewall: Status) -> Report {
        Report {
            agent: "posture test".to_string(),
            taken_at: at.parse().unwrap(),
            hostname: "kup".to_string(),
            machine_id: String::new(),
            os: Default::default(),
            kernel: String::new(),
            chassis_type: None,
            hardware: Default::default(),
            listening: None,
            listening_ports: None,
            checks: vec![
                Check::new("firewall", firewall, "inactive"),
                Check::new("os", Status::Pass, "Debian 13"),
            ],
        }
    }

    #[test]
    fn the_mail_escapes_what_the_machines_send() {
        let machines = machines::parse(&format!("kup mario.rossi@optionfactory.net {}", "a".repeat(64))).unwrap();
        let pending = Pending {
            hostname: "<img src=x>".to_string(),
            machine_id: String::new(),
            first_seen: "2026-11-19T10:00:00Z".parse().unwrap(),
        };
        let review = Review {
            attention: vec![(
                &machines[0],
                vec![Finding::Check {
                    name: "firewall".to_string(),
                    status: Status::Fail,
                    since: "2026-11-19T10:00:00Z".parse().unwrap(),
                    detail: "<b>off</b>".to_string(),
                }],
            )],
            pending: vec![("b".repeat(64), pending, "2026-11-19T11:00:00Z".parse().unwrap())],
            owner: None,
            now: "2026-11-20T08:00:00Z".parse().unwrap(),
        };
        let html = review.html(Some("https://posture.example"));
        assert!(!html.contains("<img") && !html.contains("<b>"));
        assert!(html.contains("&lt;img src=x&gt;") && html.contains("https://posture.example/machines/kup"));
    }

    #[test]
    fn a_reminder_holds_only_what_its_owner_can_fix_with_what_to_do() {
        let (a, b) = ("a".repeat(64), "b".repeat(64));
        let machines = machines::parse(&format!(
            "kup Mario.Rossi@optionfactory.net {a}\nlap luigi.verdi@optionfactory.net {b}\n"
        ))
        .unwrap();
        let pending = Pending {
            hostname: "newbox".to_string(),
            machine_id: String::new(),
            first_seen: "2026-11-19T10:00:00Z".parse().unwrap(),
        };
        let review = Review {
            attention: vec![
                (
                    &machines[0],
                    vec![
                        Finding::Check {
                            name: "firewall".to_string(),
                            status: Status::Fail,
                            since: "2026-11-19T10:00:00Z".parse().unwrap(),
                            detail: "inactive".to_string(),
                        },
                        Finding::Unreadable {
                            path: PathBuf::from("/reports/kup/x.json"),
                            error: "eof".to_string(),
                        },
                    ],
                ),
                (&machines[1], vec![Finding::Never]),
            ],
            pending: vec![("b".repeat(64), pending, "2026-11-19T11:00:00Z".parse().unwrap())],
            owner: None,
            now: "2026-11-20T08:00:00Z".parse().unwrap(),
        };

        let mario = review.of_owner("mario.rossi@optionfactory.net");
        assert_eq!(
            review.owners(),
            ["luigi.verdi@optionfactory.net", "mario.rossi@optionfactory.net"]
        );
        assert_eq!(
            mario.text(),
            "kup: firewall failing since 2026-11-19T10:00:00Z: inactive\n  to do: sudo ufw enable\n"
        );
        let html = mario.html(Some("https://posture.example/"));
        assert!(html.contains("1 of your machines needs attention") && !html.contains("newbox"));
        assert_eq!(
            mario.link("https://posture.example/"),
            "https://posture.example/people/mario.rossi%40optionfactory.net"
        );
    }

    #[test]
    fn a_failure_is_reported_once_it_lasts_longer_than_its_grace() {
        let now: Timestamp = "2026-10-26T12:30:00Z".parse().unwrap();
        let newest_first = || {
            vec![
                report("2026-10-26T12:00:00Z", Status::Fail),
                report("2026-10-26T11:00:00Z", Status::Fail),
                report("2026-10-26T10:00:00Z", Status::Fail),
                report("2026-10-26T09:00:00Z", Status::Pass),
            ]
        };
        let text = |findings: Vec<Finding>| findings.iter().map(Finding::to_string).collect::<Vec<_>>();
        let (due, within_grace) = findings(newest_first().iter(), now);
        assert_eq!(text(due), ["firewall failing since 2026-10-26T10:00:00Z: inactive"]);
        assert!(within_grace.is_empty());
        let (due, within_grace) = findings(newest_first().iter().take(2), now);
        assert!(due.is_empty());
        assert_eq!(
            text(within_grace),
            ["firewall failing since 2026-10-26T11:00:00Z: inactive"]
        );
    }

    #[test]
    fn what_a_machine_sends_stays_on_its_line() {
        let finding = Finding::Check {
            name: "firewall".to_string(),
            status: Status::Fail,
            since: "2026-11-19T10:00:00Z".parse().unwrap(),
            detail: "inactive\nlap (luigi.verdi@optionfactory.net): disk-encryption failing\x1b[2J\u{2028}\u{202e}"
                .to_string(),
        };
        assert!(!finding.to_string().contains(['\n', '\x1b', '\u{2028}', '\u{202e}']));
    }

    #[test]
    fn a_silent_machine_is_reported() {
        let now: Timestamp = "2026-11-10T00:00:00Z".parse().unwrap();
        let (findings, _) = findings([report("2026-11-01T00:00:00Z", Status::Pass)].iter(), now);
        assert_eq!(findings[0].to_string(), "no report since 2026-11-01T00:00:00Z");
    }

    #[test]
    fn a_report_from_the_future_is_reported() {
        let now: Timestamp = "2026-10-26T12:00:00Z".parse().unwrap();
        let (findings, _) = findings([report("2026-10-27T12:00:00Z", Status::Pass)].iter(), now);
        assert_eq!(findings[0].to_string(), "report from the future: 2026-10-27T12:00:00Z");
    }
}
