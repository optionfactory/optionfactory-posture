use crate::checks;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

/// The collector parses reports with this type and refuses those that do not fit, and the agents drop refused reports:
/// a field added later needs `#[serde(default)]`, or every agent older than the collector loses all its reports.
#[derive(Serialize, Deserialize)]
pub struct Report {
    pub agent: String,
    pub taken_at: Timestamp,
    pub hostname: String,
    pub machine_id: String,
    pub os: checks::os::Os,
    pub kernel: String,
    pub checks: Vec<Check>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Check {
    pub name: String,
    pub status: Status,
    pub detail: String,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Fail,
    /// The check could not run, for example a missing command: it counts as a failure.
    Unknown,
}

/// What a single check finds: whether it passed and why, or why it could not run.
pub type Outcome = Result<(bool, String), String>;

impl Check {
    pub fn new(name: &str, status: Status, detail: impl Into<String>) -> Check {
        Check {
            name: name.to_string(),
            status,
            detail: detail.into(),
        }
    }

    pub fn from_outcome(name: &str, outcome: Outcome) -> Check {
        match outcome {
            Ok((true, detail)) => Check::new(name, Status::Pass, detail),
            Ok((false, detail)) => Check::new(name, Status::Fail, detail),
            Err(e) => Check::new(name, Status::Unknown, e),
        }
    }
}

impl Report {
    pub fn take(tang_url: &str) -> Report {
        let os = checks::os::Os::read();
        let mut all = checks::disk::checks(tang_url);
        for (name, outcome) in [
            ("os", os.check()),
            ("reboot-pending", checks::reboot::check()),
            ("security-updates", checks::updates::check()),
            ("firewall", checks::firewall::check()),
            ("docker-ports", checks::docker_ports::check()),
            ("sshd", checks::sshd::check()),
            ("journal", checks::journal::check()),
            ("screen-lock", checks::screen_lock::check()),
        ] {
            all.push(Check::from_outcome(name, outcome));
        }
        Report {
            agent: concat!(env!("CARGO_PKG_NAME"), " ", env!("CARGO_PKG_VERSION")).to_string(),
            taken_at: Timestamp::now(),
            hostname: first_line("/proc/sys/kernel/hostname"),
            machine_id: first_line("/etc/machine-id"),
            os,
            kernel: first_line("/proc/sys/kernel/osrelease"),
            checks: all,
        }
    }
}

fn first_line(path: &str) -> String {
    std::fs::read_to_string(path)
        .map(|s| s.lines().next().unwrap_or("").to_string())
        .unwrap_or_default()
}
