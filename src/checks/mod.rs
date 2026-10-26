pub mod disk;
pub mod docker_ports;
pub mod firewall;
pub mod journal;
pub mod os;
pub mod reboot;
pub mod screen_lock;
pub mod sshd;
pub mod updates;

use std::process::Command;

/// Stdout of a command that must exit successfully; the error is meant for the `detail` of an unknown check.
fn stdout_of(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .output()
        .map_err(|e| format!("{program}: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("{program} {}: {}", args.join(" "), stderr.trim()));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
