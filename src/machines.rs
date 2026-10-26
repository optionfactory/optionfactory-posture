use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Unknown tokens are recorded so that an admin can approve them; the collector is public, so their number is bounded.
const MOST_PENDING: usize = 100;
/// A pending machine not heard from in a month is forgotten.
const PENDING_EXPIRY: std::time::Duration = std::time::Duration::from_secs(30 * 24 * 60 * 60);

/// A machine allowed to send reports. The collector and the review read the same list, one machine per line:
/// `<name> <owner> <sha256 of its token, hex>`. Off the list, a machine can no longer send and the review forgets it.
pub struct Machine {
    pub name: String,
    pub owner: String,
    token_sha256: String,
}

pub fn read(path: &Path) -> Result<Vec<Machine>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    parse(&text).map_err(|e| format!("{}: {e}", path.display()))
}

fn parse(text: &str) -> Result<Vec<Machine>, String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| match line.split_whitespace().collect::<Vec<_>>()[..] {
            // the name becomes the directory of its reports
            [name, owner, hash]
                if !name.is_empty()
                    && name
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                    && is_sha256(hash) =>
            {
                Ok(Machine {
                    name: name.to_string(),
                    owner: owner.to_string(),
                    token_sha256: hash.to_ascii_lowercase(),
                })
            }
            _ => Err(format!("not `<name> <owner> <sha256>`: {line}")),
        })
        .collect()
}

fn is_sha256(text: &str) -> bool {
    text.len() == 64 && text.chars().all(|c| c.is_ascii_hexdigit())
}

/// The hash of the token in an `Authorization: Bearer` header, when it looks like one an agent made.
pub fn token_sha256(authorization: Option<&str>) -> Option<String> {
    let token = authorization?.strip_prefix("Bearer ")?.trim();
    is_sha256(token).then(|| sha256_hex(token.as_bytes()))
}

pub fn approved<'a>(machines: &'a [Machine], token_sha256: &str) -> Option<&'a Machine> {
    machines.iter().find(|machine| machine.token_sha256 == token_sha256)
}

fn sha256_hex(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The token of this machine, created at the first run and readable only by root: the machine is known by it once an
/// admin approves it.
pub fn token(state: &Path) -> Result<String, String> {
    let path = state.join("token");
    match std::fs::read_to_string(&path) {
        Ok(token) => return Ok(token.trim().to_string()),
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(format!("{}: {e}", path.display())),
        Err(_) => {}
    }
    let mut random = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut urandom| urandom.read_exact(&mut random))
        .map_err(|e| format!("/dev/urandom: {e}"))?;
    let token: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    std::fs::create_dir_all(state).map_err(|e| format!("{}: {e}", state.display()))?;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut file| writeln!(file, "{token}"))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(token)
}

/// What the admin compares with the pending machine before approving it.
pub fn id(state: &Path) -> Result<(), String> {
    let token = token(state)?;
    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname").map_err(|e| format!("hostname: {e}"))?;
    println!(
        "{} {}",
        hostname.trim().to_ascii_lowercase(),
        sha256_hex(token.as_bytes())
    );
    Ok(())
}

/// A machine whose token is not on the list yet. The file's modification time is when it was last heard from.
#[derive(Serialize, Deserialize)]
pub struct Pending {
    pub hostname: String,
    pub machine_id: String,
    pub first_seen: Timestamp,
}

pub fn pending_dir(reports: &Path) -> PathBuf {
    // a dot keeps it apart from the machines, whose names have none
    reports.join(".pending")
}

/// Records or refreshes a pending machine; returns whether it is new.
pub fn record_pending(reports: &Path, token_sha256: &str, hostname: &str, machine_id: &str) -> std::io::Result<bool> {
    let dir = pending_dir(reports);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{token_sha256}.json"));
    if path.exists() {
        std::fs::File::options()
            .write(true)
            .open(&path)?
            .set_modified(SystemTime::now())?;
        return Ok(false);
    }
    if std::fs::read_dir(&dir)?.count() >= MOST_PENDING {
        return Ok(false);
    }
    let pending = Pending {
        hostname: hostname.chars().take(64).collect(),
        machine_id: machine_id.chars().take(64).collect(),
        first_seen: Timestamp::now()
            .round(jiff::Unit::Second)
            .unwrap_or(Timestamp::UNIX_EPOCH),
    };
    std::fs::write(&path, serde_json::to_vec(&pending)?)?;
    Ok(true)
}

/// The pending machines, with the hash of their token and when they were last heard from, oldest first. Approved ones
/// and those silent for a month are removed.
pub fn pending(reports: &Path, machines: &[Machine]) -> Vec<(String, Pending, Timestamp)> {
    let mut found: Vec<_> = std::fs::read_dir(pending_dir(reports))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            let hash = path.file_stem()?.to_string_lossy().into_owned();
            let modified = entry.metadata().and_then(|meta| meta.modified()).ok()?;
            let expired = modified.elapsed().is_ok_and(|age| age > PENDING_EXPIRY);
            if expired || approved(machines, &hash).is_some() {
                let _ = std::fs::remove_file(&path);
                return None;
            }
            let pending: Pending = serde_json::from_slice(&std::fs::read(&path).ok()?).ok()?;
            let last_seen = Timestamp::try_from(modified).ok()?.round(jiff::Unit::Second).ok()?;
            Some((hash, pending, last_seen))
        })
        .collect();
    found.sort_by_key(|(_, pending, _)| pending.first_seen);
    found
}

/// Prints the pending machines as entries for the list of machines, still without their owner.
pub fn print_pending(reports: &Path, machines: &[Machine]) {
    for (hash, pending, last_seen) in pending(reports, machines) {
        println!(
            "# machine-id {}, first seen {}, last seen {last_seen}",
            pending.machine_id, pending.first_seen
        );
        println!("- name: {}", pending.hostname.to_ascii_lowercase());
        println!("  owner: ");
        println!("  posture_token_sha256: {hash}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_machine_is_known_by_the_hash_of_its_token() {
        let token = "ab".repeat(32);
        let machines = parse(&format!(
            "# comment\n\nkup mario.rossi@optionfactory.net {}\n",
            sha256_hex(token.as_bytes())
        ))
        .unwrap();
        let found = |header: &str| {
            token_sha256(Some(header))
                .and_then(|hash| approved(&machines, &hash))
                .map(|machine| machine.name.as_str())
        };
        assert_eq!(found(&format!("Bearer {token}")), Some("kup"));
        assert_eq!(found(&format!("Bearer {}", "cd".repeat(32))), None);
        assert_eq!(token_sha256(Some("Bearer not-a-token")), None);
        assert!(parse("../etc owner 00").is_err());
    }
}
