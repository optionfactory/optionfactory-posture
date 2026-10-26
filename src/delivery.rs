use crate::machines;
use crate::report::Report;
use std::path::Path;
use std::time::Duration;

/// Queues the report, then sends the queue oldest first. Offline the sending fails and the queue waits for the next
/// run, so the history reaches the collector complete; that is not an error of the run.
pub fn queue_and_send(report: Report, state: &Path, collector: &str) -> Result<(), String> {
    let queue = state.join("queue");
    std::fs::create_dir_all(&queue).map_err(|e| format!("{}: {e}", queue.display()))?;
    let json = serde_json::to_vec(&report).map_err(|e| e.to_string())?;
    let name = format!("{}.json", report.taken_at.strftime("%Y%m%dT%H%M%SZ"));
    let partial = queue.join(format!(".{name}"));
    std::fs::write(&partial, &json).map_err(|e| format!("{}: {e}", partial.display()))?;
    std::fs::rename(&partial, queue.join(&name)).map_err(|e| format!("{name}: {e}"))?;

    let authorization = format!("Bearer {}", machines::token(state)?);

    let mut queued: Vec<String> = std::fs::read_dir(&queue)
        .map_err(|e| format!("{}: {e}", queue.display()))?
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".json") && !name.starts_with('.'))
        .collect();
    queued.sort();

    // on any network a spoofed DNS answer could point the collector's name elsewhere: the certificate is what stops the
    // reports and the token from going there
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
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
            Ok(_) => {}
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
