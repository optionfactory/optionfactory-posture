use super::stdout_of;
use crate::report::Outcome;

const PROFILES: [&str; 2] = ["optionfactory-workstation", "optionfactory-laptop"];

/// The baseline profile is at the version the repository publishes. unattended-upgrades skips, every day and without a
/// word, an upgrade that brings a package from an origin it does not allow yet: this is where it shows.
pub fn check() -> Outcome {
    let policy = stdout_of("apt-cache", &["policy", PROFILES[0], PROFILES[1]])?;
    Ok(evaluate(&policy))
}

fn evaluate(policy: &str) -> (bool, String) {
    let mut package = "";
    let mut installed = None;
    for line in policy.lines() {
        // one block per package: its name unindented, then `Installed:` and `Candidate:`
        if !line.starts_with(' ') {
            package = line.trim_end_matches(':');
            installed = None;
        } else if let Some(version) = line.trim().strip_prefix("Installed: ") {
            installed = Some(version).filter(|version| *version != "(none)");
        } else if let (Some(version), Some(candidate)) = (installed, line.trim().strip_prefix("Candidate: ")) {
            return match version == candidate {
                true => (true, format!("{package} {version}")),
                false => (false, format!("{package} {version}, {candidate} published")),
            };
        }
    }
    (false, format!("none of {} installed", PROFILES.join(", ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_installed_profile_is_compared_with_the_published_version() {
        let policy = |installed: &str| {
            format!(
                "optionfactory-workstation:\n  Installed: {installed}\n  Candidate: 1.0.4-1\n  Version table:\n\
                 \x20    1.0.4-1 500\n        500 https://apt.opfa.net stable/main amd64 Packages\n\
                 optionfactory-laptop:\n  Installed: (none)\n  Candidate: 1.0.4-1\n  Version table:\n"
            )
        };
        assert_eq!(
            evaluate(&policy("1.0.4-1")),
            (true, "optionfactory-workstation 1.0.4-1".into())
        );
        assert_eq!(
            evaluate(&policy("1.0.2-1")),
            (false, "optionfactory-workstation 1.0.2-1, 1.0.4-1 published".into())
        );
        assert_eq!(
            evaluate(&policy("(none)")),
            (
                false,
                "none of optionfactory-workstation, optionfactory-laptop installed".into()
            )
        );
    }
}
