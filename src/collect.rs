use crate::machines;
use crate::report::{Report, Status};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use jiff::civil::Date;
use jiff::tz::TimeZone;
use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use tokio::signal::unix::{SignalKind, signal};

/// A month of hourly reports fits, with room for a long queue coming back; past it the machine is misbehaving, and its
/// reports wait in its own queue.
const MOST_REPORTS: usize = 5_000;
/// Long enough for the review, whose longest margin is a week of silence.
const REPORT_RETENTION: SignedDuration = SignedDuration::from_hours(30 * 24);
/// Twelve months, the time between two audits.
const SUMMARY_RETENTION: SignedDuration = SignedDuration::from_hours(365 * 24);

/// What is left of a day of reports after thirty days: the worst outcome of each check, without times or details.
#[derive(Serialize, Deserialize)]
struct Summary {
    date: Date,
    hostname: String,
    checks: BTreeMap<String, Status>,
}

/// Stores the reports POSTed by the workstations, one directory per machine, and summarizes them after thirty days. It
/// sits behind nginx, which alone can reach its socket.
pub fn collect(listen: PathBuf, reports: PathBuf, machines: PathBuf) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(async move {
        let socket = listen.display();
        // the socket of the previous run stays behind and would make the bind fail
        if std::fs::symlink_metadata(&listen).is_ok_and(|meta| meta.file_type().is_socket()) {
            std::fs::remove_file(&listen).map_err(|e| format!("{socket}: {e}"))?;
        }
        let listener = tokio::net::UnixListener::bind(&listen).map_err(|e| format!("{socket}: {e}"))?;
        // who may connect is decided by who can reach the directory
        std::fs::set_permissions(&listen, std::fs::Permissions::from_mode(0o666))
            .map_err(|e| format!("{socket}: {e}"))?;
        tokio::spawn(summarize_expired_daily(reports.clone()));
        let app = Router::new()
            .route("/reports", post(store))
            .layer(DefaultBodyLimit::max(16 * 1024))
            .with_state((reports, machines));
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                match signal(SignalKind::terminate()) {
                    Ok(mut terminate) => terminate.recv().await,
                    Err(_) => std::future::pending().await,
                };
            })
            .await
            .map_err(|e| e.to_string())
    })
}

async fn store(State((reports, machines)): State<(PathBuf, PathBuf)>, headers: HeaderMap, body: Bytes) -> StatusCode {
    // read at every report, so that a machine added or taken off the list counts at once
    let machines = tokio::task::spawn_blocking(move || machines::read(&machines))
        .await
        .map_err(|e| e.to_string())
        .and_then(|read| read);
    let machines = match machines {
        Ok(machines) => machines,
        Err(e) => {
            eprintln!("optionfactory-posture: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };
    // no address is logged: it would be the employee's home
    let authorization = headers.get("authorization").and_then(|value| value.to_str().ok());
    let Some(token_sha256) = machines::token_sha256(authorization) else {
        eprintln!("optionfactory-posture: report rejected: no token");
        return StatusCode::UNAUTHORIZED;
    };
    let Some(machine) = machines::approved(&machines, &token_sha256) else {
        // the agent keeps the report, so the history arrives once the machine is approved
        if let Ok(report) = serde_json::from_slice::<Report>(&body) {
            let recorded = tokio::task::spawn_blocking(move || {
                machines::record_pending(&reports, &token_sha256, &report.hostname, &report.machine_id)
                    .map(|new| new.then_some(report.hostname))
            })
            .await;
            if let Ok(Ok(Some(hostname))) = recorded {
                eprintln!("optionfactory-posture: {hostname} is waiting for approval");
            }
        }
        return StatusCode::UNAUTHORIZED;
    };
    let (path, json, taken_at) = match destination(&reports, &machine.name, &body, Timestamp::now()) {
        Ok(accepted) => accepted,
        Err((status, reason)) => {
            eprintln!("optionfactory-posture: report from {} rejected: {reason}", machine.name);
            return status;
        }
    };
    let dir = path.parent().expect("reports go in the directory of their machine");
    let partial = dir.join(format!(".{}", path.file_name().unwrap_or_default().to_string_lossy()));
    let written = async {
        tokio::fs::create_dir_all(dir).await?;
        let mut entries = tokio::fs::read_dir(dir).await?;
        let mut count = 0;
        while entries.next_entry().await?.is_some() {
            count += 1;
        }
        if count >= MOST_REPORTS && !tokio::fs::try_exists(&path).await? {
            return Ok(StatusCode::INSUFFICIENT_STORAGE);
        }
        tokio::fs::write(&partial, &json).await?;
        // the time of arrival would tell when the machine was online: the file keeps only the time of the report
        let file = tokio::fs::OpenOptions::new().write(true).open(&partial).await?;
        file.into_std().await.set_modified(SystemTime::from(taken_at))?;
        tokio::fs::rename(&partial, &path).await?;
        Ok::<_, std::io::Error>(StatusCode::NO_CONTENT)
    };
    written.await.unwrap_or_else(|e| {
        eprintln!("optionfactory-posture: {}: {e}", path.display());
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

/// Where the report goes and what is written there: the body is parsed and written again, so only a report reaches the
/// disk, under a name the collector chose from its time. A bad report is the agent's fault, so 400 and the agent drops
/// it.
fn destination(
    reports: &Path,
    machine: &str,
    body: &[u8],
    now: Timestamp,
) -> Result<(PathBuf, Vec<u8>, Timestamp), (StatusCode, String)> {
    let report: Report = serde_json::from_slice(body).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    if report.taken_at.duration_since(now) > SignedDuration::from_hours(1) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("taken in the future, at {}", report.taken_at),
        ));
    }
    let name = format!("{}.json", report.taken_at.strftime("%Y%m%dT%H%M%SZ"));
    let json = serde_json::to_vec(&report).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok((reports.join(machine).join(name), json, report.taken_at))
}

async fn summarize_expired_daily(reports: PathBuf) {
    let mut daily = tokio::time::interval(Duration::from_secs(24 * 60 * 60));
    loop {
        daily.tick().await;
        let reports = reports.clone();
        if let Err(e) = tokio::task::spawn_blocking(move || summarize_expired(&reports, Timestamp::now())).await {
            eprintln!("optionfactory-posture: retention: {e}");
        }
    }
}

/// Report names are their UTC time at a fixed width, summary names their date: the expired ones sort before the name of
/// the cutoff.
fn summarize_expired(reports: &Path, now: Timestamp) {
    let report_cutoff = format!("{}.json", (now - REPORT_RETENTION).strftime("%Y%m%dT%H%M%SZ"));
    let summary_cutoff = format!("{}.json", (now - SUMMARY_RETENTION).strftime("%Y%m%d"));
    let dirs = match std::fs::read_dir(reports) {
        Ok(dirs) => dirs,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            eprintln!("optionfactory-posture: retention: {}: {e}", reports.display());
            return;
        }
    };
    // the pending machines, in .pending, are not machines yet
    let machine_dirs = dirs
        .flatten()
        .filter(|entry| !entry.file_name().to_string_lossy().starts_with('.'))
        .map(|entry| entry.path())
        .filter(|path| path.is_dir());
    for dir in machine_dirs {
        if let Err(e) = summarize_machine(&dir, &report_cutoff, &summary_cutoff) {
            eprintln!("optionfactory-posture: retention: {}: {e}", dir.display());
        }
    }
}

fn summarize_machine(dir: &Path, report_cutoff: &str, summary_cutoff: &str) -> std::io::Result<()> {
    let mut expired_by_day: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();
    for entry in std::fs::read_dir(dir)?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        // a partial write left by a crash expires like the report it was
        let name = name.trim_start_matches('.');
        if let Some(day) = name
            .get(..8)
            .filter(|_| name.ends_with(".json") && name < report_cutoff)
        {
            expired_by_day.entry(day.to_string()).or_default().push(entry.path());
        }
    }

    let summaries = dir.join("daily");
    for (day, mut paths) in expired_by_day {
        paths.sort();
        let path = summaries.join(format!("{day}.json"));
        let mut summary: Option<Summary> = std::fs::read(&path)
            .ok()
            .and_then(|json| serde_json::from_slice(&json).ok());
        let reports = paths
            .iter()
            .filter_map(|path| std::fs::read(path).ok())
            .filter_map(|json| serde_json::from_slice::<Report>(&json).ok());
        for report in reports {
            let summary = summary.get_or_insert_with(|| Summary {
                date: report.taken_at.to_zoned(TimeZone::UTC).date(),
                hostname: String::new(),
                checks: BTreeMap::new(),
            });
            summary.hostname = report.hostname;
            for check in report.checks {
                let worst = match (summary.checks.get(&check.name), check.status) {
                    (Some(Status::Fail), _) | (_, Status::Fail) => Status::Fail,
                    (Some(Status::Unknown), _) | (_, Status::Unknown) => Status::Unknown,
                    _ => Status::Pass,
                };
                summary.checks.insert(check.name, worst);
            }
        }
        if let Some(summary) = summary {
            std::fs::create_dir_all(&summaries)?;
            let partial = summaries.join(format!(".{day}.json"));
            std::fs::write(&partial, serde_json::to_vec(&summary)?)?;
            std::fs::rename(&partial, &path)?;
        }
        for path in paths {
            std::fs::remove_file(path)?;
        }
    }

    let entries = match std::fs::read_dir(&summaries) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".json") && name.trim_start_matches('.') < summary_cutoff {
            std::fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Check;

    fn report(at: &str, firewall: Status) -> Vec<u8> {
        serde_json::to_vec(&Report {
            agent: "posture test".to_string(),
            taken_at: at.parse().unwrap(),
            hostname: "kup".to_string(),
            machine_id: String::new(),
            os: Default::default(),
            kernel: String::new(),
            checks: vec![Check::new("firewall", firewall, "inactive")],
        })
        .unwrap()
    }

    #[test]
    fn only_a_report_is_stored_under_its_machine_and_time() {
        let now: Timestamp = "2026-10-26T12:30:00Z".parse().unwrap();
        let stored = |body: &[u8]| {
            destination(Path::new("/reports"), "kup", body, now)
                .map(|(path, _, _)| path)
                .map_err(|(status, _)| status)
        };

        assert_eq!(
            stored(&report("2026-10-26T12:00:00Z", Status::Pass)),
            Ok(PathBuf::from("/reports/kup/20261026T120000Z.json"))
        );
        assert_eq!(stored(b"{\"not\": \"a report\"}"), Err(StatusCode::BAD_REQUEST));
        assert_eq!(
            stored(&report("2026-10-27T12:00:00Z", Status::Pass)),
            Err(StatusCode::BAD_REQUEST)
        );
    }

    #[test]
    fn after_thirty_days_a_day_of_reports_becomes_its_worst_outcomes_and_after_a_year_nothing() {
        let reports = std::env::temp_dir().join(format!("optionfactory-posture-test-{}", std::process::id()));
        let machine = reports.join("kup");
        std::fs::create_dir_all(machine.join("daily")).unwrap();
        let files = [
            ("20260915T080000Z.json", report("2026-09-15T08:00:00Z", Status::Fail)),
            ("20260915T150000Z.json", report("2026-09-15T15:00:00Z", Status::Pass)),
            (".20260915T160000Z.json", b"{\"partial".to_vec()),
            ("20261020T120000Z.json", report("2026-10-20T12:00:00Z", Status::Pass)),
            ("daily/20251020.json", b"{}".to_vec()),
        ];
        for (name, content) in files {
            std::fs::write(machine.join(name), content).unwrap();
        }

        summarize_expired(&reports, "2026-10-26T12:30:00Z".parse().unwrap());

        let names = |dir: &Path| {
            let mut names: Vec<_> = std::fs::read_dir(dir)
                .unwrap()
                .flatten()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        };
        let left = names(&machine);
        let summaries = names(&machine.join("daily"));
        let summary = std::fs::read_to_string(machine.join("daily/20260915.json")).unwrap();
        std::fs::remove_dir_all(&reports).unwrap();
        assert_eq!(left, ["20261020T120000Z.json", "daily"]);
        assert_eq!(summaries, ["20260915.json"]);
        assert_eq!(
            summary,
            r#"{"date":"2026-09-15","hostname":"kup","checks":{"firewall":"fail"}}"#
        );
    }
}
