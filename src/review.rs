use crate::machines::{self, Machine, Pending};
use crate::report::{Report, Status};
use crate::web::pages::escape;
use jiff::{SignedDuration, Timestamp};
use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::Path;

/// Laptops off the VPN, on holiday or switched off keep their reports queued: a week of silence is the limit.
const LONGEST_SILENCE: SignedDuration = SignedDuration::from_hours(7 * 24);

/// How long a check may keep failing before it is reported.
fn grace(check: &str) -> SignedDuration {
    match check {
        // turned off for development
        "firewall" => SignedDuration::from_hours(2),
        // unattended-upgrades runs once a day
        "security-updates" => SignedDuration::from_hours(48),
        // offline, the kernel stops calling the clock synchronized after some hours
        "clock-sync" => SignedDuration::from_hours(24),
        _ => SignedDuration::from_hours(4),
    }
}

/// The reports of a machine are in `<reports>/<name>/`, the directory the collector chose from the token the report
/// carried: the machine cannot write under another one's name. The list tells whose machine it is, and which machines
/// should be reporting at all.
///
/// With `html`, the same as a mail body, linking to the pages at `pages_url` when given; nothing when nothing needs
/// attention.
pub fn review(reports: &Path, machines: &[Machine], html: bool, pages_url: Option<&str>) -> Result<(), String> {
    let now = Timestamp::now();
    let attention: Vec<(&Machine, Vec<String>)> = machines
        .iter()
        .map(|machine| (machine, reviewed(reports, machine, now).1))
        .filter(|(_, findings)| !findings.is_empty())
        .collect();
    let pending = machines::pending(reports, machines)?;
    if html {
        if !attention.is_empty() || !pending.is_empty() {
            print!("{}", mail(&attention, &pending, pages_url, now));
        }
        return Ok(());
    }
    for (machine, findings) in &attention {
        for finding in findings {
            println!("{} ({}): {finding}", machine.name, machine.owner);
        }
    }
    for (hash, pending, _) in &pending {
        println!(
            "{}: waiting for approval since {}, token {}",
            pending.hostname,
            pending.first_seen,
            &hash[..8]
        );
    }
    Ok(())
}

const FONT: &str = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
const MUTED: &str = "#475569";
const BORDER: &str = "#cbd5e1";
const PRIMARY: &str = "#0369a1";
const DANGER: &str = "#b91c1c";
const WARNING: &str = "#b45309";

/// Tables and inline styles, the light palette of the pages: mail clients drop stylesheets and most of CSS.
fn mail(
    attention: &[(&Machine, Vec<String>)],
    pending: &[(String, Pending, Timestamp)],
    pages_url: Option<&str>,
    now: Timestamp,
) -> String {
    let pages_url = pages_url.map(|url| escape(url.trim_end_matches('/')));
    let mut summary = Vec::new();
    match attention.len() {
        0 => {}
        1 => summary.push("1 machine needs attention".to_string()),
        n => summary.push(format!("{n} machines need attention")),
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
            escape(&machine.owner)
        );
        for finding in findings {
            let _ = writeln!(html, "<li>{}</li>", escape(finding));
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
        let _ = writeln!(
            html,
            "<tr><td style=\"padding:14px 4px 0;\"><a href=\"{url}\" style=\"display:inline-block;padding:9px 18px;\
             background:{PRIMARY};color:#ffffff;border-radius:6px;font-size:14px;font-weight:600;\
             text-decoration:none;\">Open the posture pages</a></td></tr>"
        );
    }
    let _ = write!(
        html,
        "<tr><td style=\"padding:18px 4px 0;font-size:12px;color:{MUTED};\">Times are UTC.</td></tr>\n\
         </table></td></tr></table>\n</body></html>\n"
    );
    html
}

/// The reports of a machine, newest first, and what needs attention about it.
pub fn reviewed(reports: &Path, machine: &Machine, now: Timestamp) -> (Vec<Report>, Vec<String>) {
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
                Err(e) => {
                    unreadable.push(format!("unreadable report {}: {e}", path.display()));
                    None
                }
            }
        })
        .collect();
    let mut lines = findings(newest_first.iter(), now);
    lines.extend(unreadable);
    // reports go after thirty days, summaries after a year: a machine silent that long is told by its summaries
    let latest_summary = std::fs::read_dir(dir.join("daily"))
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".json") && !name.starts_with('.'))
        .max();
    match (has_reports, latest_summary) {
        (true, _) => {}
        (false, Some(day)) => lines.push(format!("no report since {}", day.trim_end_matches(".json"))),
        (false, None) => lines.push("never reported".to_string()),
    }
    (newest_first, lines)
}

/// Reads back only as far as needed to find when each failing check last passed.
fn findings<'a>(mut newest_first: impl Iterator<Item = &'a Report>, now: Timestamp) -> Vec<String> {
    let Some(latest) = newest_first.next() else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    // a clock far ahead keeps this report the newest, hiding the ones that follow
    if latest.taken_at.duration_since(now) > SignedDuration::from_hours(1) {
        findings.push(format!("report from the future: {}", latest.taken_at));
    }
    if now.duration_since(latest.taken_at) > LONGEST_SILENCE {
        findings.push(format!("no report since {}", latest.taken_at));
    }
    let mut failing: BTreeMap<String, (Timestamp, String)> = latest
        .checks
        .iter()
        .filter(|check| check.status != Status::Pass)
        .map(|check| (check.name.clone(), (latest.taken_at, check.detail.clone())))
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
    for (name, (since, detail)) in failing {
        if now.duration_since(since) >= grace(&name) {
            findings.push(format!("{name} failing since {since}: {detail}"));
        }
    }
    findings
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
        let html = mail(
            &[(
                &machines[0],
                vec!["firewall failing since 2026-11-19T10:00:00Z: <b>off</b>".to_string()],
            )],
            &[("b".repeat(64), pending, "2026-11-19T11:00:00Z".parse().unwrap())],
            Some("https://posture.example"),
            "2026-11-20T08:00:00Z".parse().unwrap(),
        );
        assert!(!html.contains("<img") && !html.contains("<b>"));
        assert!(html.contains("&lt;img src=x&gt;") && html.contains("https://posture.example/machines/kup"));
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
        assert_eq!(
            findings(newest_first().iter(), now),
            ["firewall failing since 2026-10-26T10:00:00Z: inactive"]
        );
        assert!(findings(newest_first().iter().take(2), now).is_empty());
    }

    #[test]
    fn a_silent_machine_is_reported() {
        let now: Timestamp = "2026-11-10T00:00:00Z".parse().unwrap();
        let findings = findings([report("2026-11-01T00:00:00Z", Status::Pass)].iter(), now);
        assert_eq!(findings, ["no report since 2026-11-01T00:00:00Z"]);
    }

    #[test]
    fn a_report_from_the_future_is_reported() {
        let now: Timestamp = "2026-10-26T12:00:00Z".parse().unwrap();
        let findings = findings([report("2026-10-27T12:00:00Z", Status::Pass)].iter(), now);
        assert_eq!(findings, ["report from the future: 2026-10-27T12:00:00Z"]);
    }
}
