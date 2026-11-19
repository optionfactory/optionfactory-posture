use crate::report::Outcome;

/// No account logs in without a password: an empty second field of `/etc/shadow`. Only their number is reported,
/// never the names.
pub fn check() -> Outcome {
    let shadow = std::fs::read_to_string("/etc/shadow").map_err(|e| format!("/etc/shadow: {e}"))?;
    match without_password(&shadow) {
        0 => Ok((true, "every account has a password or is locked".into())),
        1 => Ok((false, "1 account without a password".into())),
        accounts => Ok((false, format!("{accounts} accounts without a password"))),
    }
}

fn without_password(shadow: &str) -> usize {
    shadow.lines().filter(|line| line.split(':').nth(1) == Some("")).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_empty_password_field_counts() {
        let shadow = "root:*:20000:0:99999:7:::\nmario:$y$j9T$abc:20000:0:99999:7:::\nguest::20000:0:99999:7:::\n\
                      daemon:!:20000::::::\n";
        assert_eq!(without_password(shadow), 1);
    }
}
