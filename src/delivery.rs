use crate::machines;
use crate::report::Report;
use jiff::{SignedDuration, Timestamp};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

/// The collector refuses reports older than this, which it would summarize at once: a machine never approved, or long
/// away from the collector, drops them instead of growing its queue.
const QUEUE_RETENTION: SignedDuration = SignedDuration::from_hours(30 * 24);

/// Queues the report, then sends the queue oldest first. Offline the sending fails and the queue waits for the next
/// run, so the history reaches the collector complete; that is not an error of the run. The queue is readable only by
/// root, whoever starts the agent and whatever the unit says.
pub fn queue_and_send(report: Report, state: &Path, collector: &str) -> Result<(), String> {
    let queue = state.join("queue");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&queue)
        .and_then(|()| std::fs::set_permissions(&queue, std::fs::Permissions::from_mode(0o700)))
        .map_err(|e| format!("{}: {e}", queue.display()))?;
    let json = serde_json::to_vec(&report).map_err(|e| e.to_string())?;
    let name = format!("{}.json", report.taken_at.strftime("%Y%m%dT%H%M%SZ"));
    let partial = queue.join(format!(".{name}"));
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&partial)
        .and_then(|mut file| file.write_all(&json))
        .map_err(|e| format!("{}: {e}", partial.display()))?;
    std::fs::rename(&partial, queue.join(&name)).map_err(|e| format!("{name}: {e}"))?;

    let authorization = format!("Bearer {}", machines::token(state)?);

    // names are times at a fixed width: the expired ones sort before the cutoff
    let cutoff = format!(
        "{}.json",
        (Timestamp::now() - QUEUE_RETENTION).strftime("%Y%m%dT%H%M%SZ")
    );
    let mut queued = Vec::new();
    let mut expired = 0;
    for entry in std::fs::read_dir(&queue)
        .map_err(|e| format!("{}: {e}", queue.display()))?
        .flatten()
    {
        let name = entry.file_name().to_string_lossy().into_owned();
        match (name.ends_with(".json") && !name.starts_with('.'), name < cutoff) {
            (false, _) => {}
            (true, true) => {
                expired += 1;
                let _ = std::fs::remove_file(entry.path());
            }
            (true, false) => queued.push(name),
        }
    }
    if expired > 0 {
        eprintln!("optionfactory-posture: {expired} reports older than thirty days dropped from the queue");
    }
    queued.sort();

    // on any network a spoofed DNS answer could point the collector's name elsewhere: the certificate is what stops the
    // reports and the token from going there. No redirect is followed: the collector cannot send the machine elsewhere
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(20)))
        .build()
        .into();
    for (sent, name) in queued.iter().enumerate() {
        let path = queue.join(name);
        let body = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        match agent
            .post(collector)
            .header("Content-Type", "application/json")
            .header("Authorization", &authorization)
            .send(&body[..])
        {
            Ok(response) if response.status().is_success() => {}
            // a redirect, say: only a stored report leaves the queue
            Ok(response) => {
                eprintln!(
                    "optionfactory-posture: {collector}: answered {}; {} reports left in the queue",
                    response.status(),
                    queued.len() - sent
                );
                return Ok(());
            }
            // the collector will never take this one (a clock far ahead, say): keeping it would block the queue
            Err(ureq::Error::StatusCode(code @ (400 | 413))) => {
                eprintln!("optionfactory-posture: {collector}: {name} refused with {code}, dropped");
            }
            Err(e) => {
                eprintln!(
                    "optionfactory-posture: {collector}: {e}; {} reports left in the queue",
                    queued.len() - sent
                );
                return Ok(());
            }
        }
        std::fs::remove_file(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok(())
}
