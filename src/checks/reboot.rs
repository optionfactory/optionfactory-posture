use crate::report::Outcome;
use jiff::{SignedDuration, Timestamp};

/// Nothing reboots by itself: the owner reboots when it suits them, and a week is their margin.
const LONGEST_PENDING: SignedDuration = SignedDuration::from_hours(7 * 24);

pub fn check() -> Outcome {
    let since = match std::fs::metadata("/var/run/reboot-required").and_then(|m| m.modified()) {
        Ok(modified) => modified,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((true, "no reboot pending".into())),
        Err(e) => return Err(format!("/var/run/reboot-required: {e}")),
    };
    let since = Timestamp::try_from(since).unwrap_or(Timestamp::UNIX_EPOCH);
    let overdue = Timestamp::now().duration_since(since) > LONGEST_PENDING;
    Ok((!overdue, format!("reboot pending since {since}")))
}
