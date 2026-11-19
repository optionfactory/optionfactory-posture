use crate::report::Outcome;
use std::path::PathBuf;

/// No display manager logs anyone in by itself: whoever switches the machine on would get the session, with the disk
/// that Tang unlocks in the office. LightDM (Cinnamon), GDM (GNOME) and SDDM (KDE), each read as it reads itself: its
/// files in order, the last value winning. The detail never names the user.
pub fn check() -> Outcome {
    let lightdm = configs(
        &["/usr/share/lightdm/lightdm.conf.d", "/etc/lightdm/lightdm.conf.d"],
        &["/etc/lightdm/lightdm.conf"],
    );
    let gdm = configs(&[], &["/etc/gdm3/daemon.conf", "/etc/gdm3/custom.conf"]);
    let sddm = configs(&["/usr/lib/sddm/sddm.conf.d", "/etc/sddm.conf.d"], &["/etc/sddm.conf"]);
    let seat = |section: &str| section.starts_with("Seat");
    let enabled = |value: &str| value.eq_ignore_ascii_case("true") || value == "1";
    let mut found = Vec::new();
    for (key, wrong) in [("autologin-user", "a user"), ("autologin-guest", "the guest")] {
        if let Some((value, file)) = last_value(&lightdm, seat, key)
            && !value.is_empty()
            && value != "false"
        {
            found.push(format!("LightDM logs {wrong} in ({file})"));
        }
    }
    for key in ["AutomaticLoginEnable", "TimedLoginEnable"] {
        if let Some((value, file)) = last_value(&gdm, |section| section == "daemon", key)
            && enabled(&value)
        {
            found.push(format!("GDM {key} ({file})"));
        }
    }
    if let Some((value, file)) = last_value(&sddm, |section| section == "Autologin", "User")
        && !value.is_empty()
    {
        found.push(format!("SDDM logs a user in ({file})"));
    }
    match found.is_empty() {
        true => Ok((true, "no automatic login".into())),
        false => Ok((false, found.join(", "))),
    }
}

/// The `.conf` files of each directory in name order, then the single files; missing ones are left out.
fn configs(dirs: &[&str], files: &[&str]) -> Vec<(PathBuf, String)> {
    let mut paths = Vec::new();
    for dir in dirs {
        let mut in_dir: Vec<PathBuf> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "conf"))
            .collect();
        in_dir.sort();
        paths.extend(in_dir);
    }
    paths.extend(files.iter().map(PathBuf::from));
    paths
        .into_iter()
        .filter_map(|path| Some((path.clone(), std::fs::read_to_string(path).ok()?)))
        .collect()
}

/// The last value of `key` in a section `section` accepts, with the file that sets it.
fn last_value(configs: &[(PathBuf, String)], section: impl Fn(&str) -> bool, key: &str) -> Option<(String, String)> {
    let mut last = None;
    for (path, text) in configs {
        let mut current = String::new();
        for line in text.lines().map(str::trim) {
            if let Some(name) = line.strip_prefix('[').and_then(|line| line.strip_suffix(']')) {
                current = name.to_string();
            } else if !line.starts_with('#')
                && !line.starts_with(';')
                && section(&current)
                && let Some((name, value)) = line.split_once('=')
                && name.trim() == key
            {
                last = Some((value.trim().to_string(), path.display().to_string()));
            }
        }
    }
    last
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_last_file_setting_a_key_in_its_section_wins() {
        let configs = [
            (
                PathBuf::from("/usr/share/lightdm/lightdm.conf.d/50-auto.conf"),
                "[Seat:*]\nautologin-user=mario\n".to_string(),
            ),
            (
                PathBuf::from("/etc/lightdm/lightdm.conf"),
                "[Seat:*]\n#autologin-user=luigi\n[Greeter]\nautologin-user=luigi\n[SeatDefaults]\nautologin-user=\n"
                    .to_string(),
            ),
        ];
        let seat = |section: &str| section.starts_with("Seat");

        assert_eq!(
            last_value(&configs[..1], seat, "autologin-user"),
            Some((
                "mario".to_string(),
                "/usr/share/lightdm/lightdm.conf.d/50-auto.conf".to_string()
            ))
        );
        assert_eq!(
            last_value(&configs, seat, "autologin-user"),
            Some((String::new(), "/etc/lightdm/lightdm.conf".to_string()))
        );
    }
}
