use super::stdout_of;
use crate::report::Outcome;

/// The journal survives reboots: with `Storage=auto`, the default, only when `/var/log/journal` exists.
pub fn check() -> Outcome {
    let config = stdout_of("systemd-analyze", &["cat-config", "systemd/journald.conf"])?;
    let storage = config
        .lines()
        .rev()
        .find_map(|line| line.trim().strip_prefix("Storage="))
        .unwrap_or("auto");
    let persistent = match storage {
        "persistent" => true,
        "auto" => std::path::Path::new("/var/log/journal").is_dir(),
        _ => false,
    };
    match persistent {
        true => Ok((true, format!("Storage={storage}, persistent"))),
        false => Ok((false, format!("Storage={storage}, lost at every reboot"))),
    }
}
