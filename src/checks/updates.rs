use super::stdout_of;
use crate::report::Outcome;

/// Security updates that apt would install now, from the package lists that apt-daily already refreshes.
pub fn check() -> Outcome {
    let simulation = stdout_of("apt-get", &["-s", "-o", "Debug::NoLocking=1", "dist-upgrade"])?;
    Ok(evaluate(&simulation))
}

fn evaluate(simulation: &str) -> (bool, String) {
    let pending: Vec<&str> = simulation
        .lines()
        .filter(|line| line.starts_with("Inst ") && (line.contains("-security") || line.contains("Debian-Security")))
        .filter_map(|line| line.split_whitespace().nth(1))
        .collect();
    if pending.is_empty() {
        return (true, "none pending".into());
    }
    // the names of a few are enough: after weeks offline the whole list would not fit in a report
    let detail = format!(
        "{} pending: {}{}",
        pending.len(),
        pending.iter().take(10).copied().collect::<Vec<_>>().join(" "),
        if pending.len() > 10 { " ..." } else { "" }
    );
    (false, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_security_updates_count() {
        let simulation = "Reading package lists...\n\
            Inst libssl3t64 [3.0.13-0ubuntu3.5] (3.0.13-0ubuntu3.6 Ubuntu:24.04/noble-security [amd64])\n\
            Inst firefox [140.0] (141.0 linuxmint:22.3/zena [amd64])\n\
            Inst openssh-client [1:10.0p1-7] (1:10.0p1-7+deb13u1 Debian-Security:13/stable-security [amd64])\n\
            Conf libssl3t64 (3.0.13-0ubuntu3.6 Ubuntu:24.04/noble-security [amd64])\n";
        assert_eq!(
            evaluate(simulation),
            (false, "2 pending: libssl3t64 openssh-client".into())
        );
        assert!(evaluate("Inst firefox [140.0] (141.0 linuxmint:22.3/zena [amd64])\n").0);
    }
}
