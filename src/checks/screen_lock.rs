use super::stdout_of;
use crate::report::Outcome;

/// The baseline locks the screen after at most 15 minutes of idle time.
const LONGEST_IDLE_SECONDS: u32 = 15 * 60;

/// Checks the system defaults (`dconf read -d`) the baseline sets and locks, since root cannot see the settings of the
/// users' sessions: a locked default is what every session gets.
pub fn check() -> Outcome {
    let prefix = match (
        std::path::Path::new("/usr/bin/cinnamon").exists(),
        std::path::Path::new("/usr/bin/gnome-shell").exists(),
    ) {
        (true, _) => "/org/cinnamon/desktop",
        (false, true) => "/org/gnome/desktop",
        (false, false) => return Err("neither Cinnamon nor GNOME installed".into()),
    };
    let lock_enabled = format!("{prefix}/screensaver/lock-enabled");
    let idle_delay = format!("{prefix}/session/idle-delay");
    let read = |key: &str| stdout_of("dconf", &["read", "-d", key]).map(|value| value.trim().to_string());
    let enabled = read(&lock_enabled)?;
    let delay = read(&idle_delay)?;
    let locks = locked_keys();
    let seconds: Option<u32> = delay.trim_start_matches("uint32 ").parse().ok();
    let mut wrong = Vec::new();
    if enabled != "true" {
        wrong.push(format!("{lock_enabled} is '{enabled}'"));
    }
    if !seconds.is_some_and(|s| s > 0 && s <= LONGEST_IDLE_SECONDS) {
        wrong.push(format!("{idle_delay} is '{delay}'"));
    }
    for key in [&lock_enabled, &idle_delay] {
        if !locks.contains(key) {
            wrong.push(format!("{key} not locked"));
        }
    }
    match wrong.is_empty() {
        true => Ok((true, format!("locks after {} seconds", seconds.unwrap_or_default()))),
        false => Ok((false, wrong.join(", "))),
    }
}

/// dconf has no command to list locks: they are the lines of the files in `/etc/dconf/db/<db>.d/locks/`.
fn locked_keys() -> Vec<String> {
    let Ok(databases) = std::fs::read_dir("/etc/dconf/db") else {
        return Vec::new();
    };
    databases
        .flatten()
        .filter_map(|db| std::fs::read_dir(db.path().join("locks")).ok())
        .flat_map(|files| files.flatten())
        .filter_map(|file| std::fs::read_to_string(file.path()).ok())
        .flat_map(|content| content.lines().map(|line| line.trim().to_string()).collect::<Vec<_>>())
        .collect()
}
