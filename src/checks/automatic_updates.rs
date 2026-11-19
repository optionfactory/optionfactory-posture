use super::stdout_of;
use crate::report::Outcome;

/// unattended-upgrades runs every day, refreshing the package lists first: `security-updates` sees the updates still
/// missing, this the setting that installs them.
pub fn check() -> Outcome {
    if !std::path::Path::new("/usr/bin/unattended-upgrade").exists() {
        return Ok((false, "unattended-upgrades not installed".into()));
    }
    let dump = stdout_of("apt-config", &["dump"])?;
    let off: Vec<String> = [
        "APT::Periodic::Update-Package-Lists",
        "APT::Periodic::Unattended-Upgrade",
    ]
    .into_iter()
    .filter_map(|key| {
        // `APT::Periodic::Unattended-Upgrade "1";`: a number of days, or `always`
        let value = dump
            .lines()
            .rev()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix(' '))
            .map(|value| value.trim().trim_end_matches(';').trim_matches('"').to_string())
            .unwrap_or_default();
        (value.is_empty() || value == "0").then(|| format!("{key} is '{value}'"))
    })
    .collect();
    match off.is_empty() {
        true => Ok((true, "unattended-upgrades runs every day".into())),
        false => Ok((false, off.join(", "))),
    }
}
