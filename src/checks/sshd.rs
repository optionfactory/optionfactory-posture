use super::stdout_of;
use crate::report::Outcome;

/// Login only with step-ca certificates: no passwords, no root.
const EXPECTED: [(&str, &str); 3] = [
    ("passwordauthentication", "no"),
    ("kbdinteractiveauthentication", "no"),
    ("permitrootlogin", "no"),
];

pub fn check() -> Outcome {
    let effective = stdout_of("sshd", &["-T"])?;
    Ok(evaluate(&effective))
}

fn evaluate(effective: &str) -> (bool, String) {
    let value = |key: &str| {
        effective
            .lines()
            .find_map(|line| line.strip_prefix(key).and_then(|rest| rest.strip_prefix(' ')))
            .unwrap_or("")
    };
    let mut wrong: Vec<String> = EXPECTED
        .iter()
        .filter(|(key, expected)| value(key) != *expected)
        .map(|(key, _)| format!("{key} {}", value(key)))
        .collect();
    if matches!(value("trustedusercakeys"), "" | "none") {
        wrong.push("trustedusercakeys none".to_string());
    }
    match wrong.is_empty() {
        true => (true, "certificates only, no passwords, no root".into()),
        false => (false, wrong.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords_and_root_must_be_off_and_the_ca_trusted() {
        let good = "port 22\npasswordauthentication no\nkbdinteractiveauthentication no\npermitrootlogin no\n\
            trustedusercakeys /etc/ssh/ca.pub\n";
        assert!(evaluate(good).0);
        let bad = good
            .replace("permitrootlogin no", "permitrootlogin prohibit-password")
            .replace("/etc/ssh/ca.pub", "none");
        assert_eq!(
            evaluate(&bad),
            (
                false,
                "permitrootlogin prohibit-password, trustedusercakeys none".into()
            )
        );
    }
}
