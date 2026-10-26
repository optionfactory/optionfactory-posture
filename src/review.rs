use crate::machines::{self, Machine};
use crate::report::{Report, Status};
use jiff::{SignedDuration, Timestamp};
use std::collections::BTreeMap;
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
        _ => SignedDuration::from_hours(4),
    }
}

/// The reports of a machine are in `<reports>/<name>/`, the directory the collector chose from the token the report
/// carried: the machine cannot write under another one's name. The list tells whose machine it is, and which machines
/// should be reporting at all.
pub fn review(reports: &Path, machines: &[Machine]) -> Result<(), String> {
    let now = Timestamp::now();
    for machine in machines {
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
        let mut lines = findings(newest_first.into_iter(), now);
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
        for finding in lines {
            println!("{} ({}): {finding}", machine.name, machine.owner);
        }
    }
    for (hash, pending, _) in machines::pending(reports, machines) {
        println!(
            "{}: waiting for approval since {}, token {}",
            pending.hostname,
            pending.first_seen,
            &hash[..8]
        );
    }
    Ok(())
}

/// Reads back only as far as needed to find when each failing check last passed.
fn findings(mut newest_first: impl Iterator<Item = Report>, now: Timestamp) -> Vec<String> {
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
            checks: vec![
                Check::new("firewall", firewall, "inactive"),
                Check::new("os", Status::Pass, "Debian 13"),
            ],
        }
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
            findings(newest_first().into_iter(), now),
            ["firewall failing since 2026-10-26T10:00:00Z: inactive"]
        );
        assert!(findings(newest_first().into_iter().take(2), now).is_empty());
    }

    #[test]
    fn a_silent_machine_is_reported() {
        let now: Timestamp = "2026-11-10T00:00:00Z".parse().unwrap();
        let findings = findings([report("2026-11-01T00:00:00Z", Status::Pass)].into_iter(), now);
        assert_eq!(findings, ["no report since 2026-11-01T00:00:00Z"]);
    }

    #[test]
    fn a_report_from_the_future_is_reported() {
        let now: Timestamp = "2026-10-26T12:00:00Z".parse().unwrap();
        let findings = findings([report("2026-10-27T12:00:00Z", Status::Pass)].into_iter(), now);
        assert_eq!(findings, ["report from the future: 2026-10-27T12:00:00Z"]);
    }
}
