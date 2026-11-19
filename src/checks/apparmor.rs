use crate::report::Outcome;

/// AppArmor is on, with profiles in enforce mode: Debian and Ubuntu turn it on by default, so off means someone turned
/// it off.
pub fn check() -> Outcome {
    match std::fs::read_to_string("/sys/module/apparmor/parameters/enabled") {
        Ok(enabled) if enabled.trim() == "Y" => {}
        Ok(_) => return Ok((false, "disabled".into())),
        Err(_) => return Ok((false, "not in the kernel".into())),
    }
    let profiles = std::fs::read_to_string("/sys/kernel/security/apparmor/profiles")
        .map_err(|e| format!("/sys/kernel/security/apparmor/profiles: {e}"))?;
    // one profile per line: `name (enforce)`, `name (complain)`, ...
    let count = |mode: &str| {
        profiles
            .lines()
            .filter(|line| line.ends_with(&format!("({mode})")))
            .count()
    };
    let (enforce, complain) = (count("enforce"), count("complain"));
    let detail = format!("{enforce} profiles enforced, {complain} in complain mode");
    Ok((enforce > 0, detail))
}
