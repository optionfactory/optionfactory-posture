pub mod apparmor;
pub mod auto_login;
pub mod automatic_updates;
pub mod baseline;
pub mod clock_sync;
pub mod disk;
pub mod docker_ports;
pub mod empty_passwords;
pub mod firewall;
pub mod journal;
pub mod os;
pub mod reboot;
pub mod screen_lock;
pub mod sshd;
pub mod updates;

/// What a check verifies, in a few words: the table of the README, for the pages.
pub fn about(check: &str) -> Option<&'static str> {
    Some(match check {
        "disk-encryption" => "every fixed disk is encrypted with LUKS2, except the EFI system partition and /boot",
        "disk-recovery-keyslot" => "every LUKS2 device has a recovery passphrase besides Clevis",
        "disk-tang" => "every LUKS2 device is bound to the Tang server of the office",
        "os" => "the system is a supported release",
        "reboot-pending" => "no reboot has been pending for more than 7 days",
        "security-updates" => "no security update is waiting to be installed",
        "automatic-updates" => "unattended-upgrades refreshes the package lists and installs the updates every day",
        "baseline" => "the installed baseline profile is the published version",
        "firewall" => "ufw is active and denies incoming connections by default",
        "docker-ports" => "no container port is published on every interface, where Docker bypasses ufw",
        "sshd" => "the SSH server takes no password and no root login, and trusts the company certificates",
        "empty-passwords" => "no account is without a password",
        "apparmor" => "AppArmor is on, with its profiles enforced",
        "journal" => "the system journal survives reboots",
        "clock-sync" => "the clock is synchronized over the network",
        "screen-lock" => "the screen locks after at most 15 minutes, and the setting is locked",
        "auto-login" => "nobody is logged in automatically at boot",
        _ => return None,
    })
}

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// A command still running after this is stuck (`nvidia-smi` with a GPU in a bad state, `docker ps` with a stuck
/// daemon): killed, it leaves its check unknown instead of holding back the whole report.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);

/// Stdout of a command that must exit successfully; the error is meant for the `detail` of an unknown check.
pub(crate) fn stdout_of(program: &str, args: &[&str]) -> Result<String, String> {
    stdout_within(program, args, COMMAND_TIMEOUT)
}

fn stdout_within(program: &str, args: &[&str], timeout: Duration) -> Result<String, String> {
    let mut child = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{program}: {e}"))?;
    // read while it runs, or a full pipe would stop it
    let drain = |pipe: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            if let Some(mut pipe) = pipe {
                let _ = pipe.read_to_end(&mut bytes);
            }
            bytes
        })
    };
    let stdout = drain(child.stdout.take().map(|pipe| Box::new(pipe) as Box<dyn Read + Send>));
    let stderr = drain(child.stderr.take().map(|pipe| Box::new(pipe) as Box<dyn Read + Send>));
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait().map_err(|e| format!("{program}: {e}"))? {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                // the readers are left behind: a child of the command may still hold the pipes open
                return Err(format!(
                    "{program} {}: no answer in {} seconds",
                    args.join(" "),
                    timeout.as_secs()
                ));
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    };
    let stdout = stdout.join().unwrap_or_default();
    if !status.success() {
        let stderr = stderr.join().unwrap_or_default();
        return Err(format!(
            "{program} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stuck_command_is_killed_and_its_check_left_unknown() {
        let started = Instant::now();
        let stuck = stdout_within("sleep", &["30"], Duration::from_millis(200));
        assert_eq!(stuck, Err("sleep 30: no answer in 0 seconds".to_string()));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(stdout_within("echo", &["ok"], COMMAND_TIMEOUT), Ok("ok\n".to_string()));
    }
}
