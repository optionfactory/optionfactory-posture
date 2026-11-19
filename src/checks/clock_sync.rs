use super::stdout_of;
use crate::report::Outcome;

/// The clock is synchronized over the network, by systemd-timesyncd or any other client: the times of the logs and of
/// the reports, and the checks of certificates, depend on it. Without a server the kernel stops calling the clock
/// synchronized after some hours: the review waits a day.
pub fn check() -> Outcome {
    let show = stdout_of("timedatectl", &["show", "-p", "NTP", "-p", "NTPSynchronized"])?;
    let value = |key: &str| {
        show.lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
            .unwrap_or("")
            .to_string()
    };
    match (value("NTP").as_str(), value("NTPSynchronized").as_str()) {
        (_, "yes") => Ok((true, "synchronized".into())),
        ("yes", _) => Ok((false, "NTP on, not synchronized".into())),
        _ => Ok((false, "NTP off, not synchronized".into())),
    }
}
