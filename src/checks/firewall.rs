use super::stdout_of;
use crate::report::Outcome;

/// ufw active and denying (or rejecting) incoming connections by default. Developers may turn it off for a while: the review
/// tolerates that for a couple of hours.
pub fn check() -> Outcome {
    let status = stdout_of("ufw", &["status", "verbose"])?;
    let active = status.lines().any(|line| line.trim() == "Status: active");
    let deny_incoming = status
        .lines()
        .any(|line| line.starts_with("Default: deny (incoming)") || line.starts_with("Default: reject (incoming)"));
    match (active, deny_incoming) {
        (true, true) => Ok((true, "active, incoming denied by default".into())),
        (false, _) => Ok((false, "inactive".into())),
        (true, false) => Ok((false, "active, but incoming allowed by default".into())),
    }
}
