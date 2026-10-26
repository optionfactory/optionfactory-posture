use super::stdout_of;
use crate::report::{Check, Status};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

const ENCRYPTION: &str = "disk-encryption";
const RECOVERY: &str = "disk-recovery-keyslot";
const TANG: &str = "disk-tang";

const ESP_PARTITION_TYPES: [&str; 2] = ["c12a7328-f81f-11d2-ba4b-00a0c93ec93b", "0xef"];

/// Every fixed disk, not only the one holding `/`: a second data disk, a swap partition or an old installation on
/// another drive leak as much as an unencrypted root.
pub fn checks(tang_url: &str) -> Vec<Check> {
    let devices = stdout_of(
        "lsblk",
        &["-J", "-o", "NAME,PATH,TYPE,FSTYPE,FSVER,RM,TRAN,PARTTYPE,MOUNTPOINTS"],
    );
    let tree: Lsblk = match devices.and_then(|json| serde_json::from_str(&json).map_err(|e| format!("lsblk: {e}"))) {
        Ok(tree) => tree,
        Err(e) => {
            return [ENCRYPTION, RECOVERY, TANG]
                .iter()
                .map(|name| Check::new(name, Status::Unknown, &e))
                .collect();
        }
    };
    let mut clear = Vec::new();
    let mut luks = Vec::new();
    for disk in tree.blockdevices.iter().filter(|device| device.is_fixed_disk()) {
        disk.sort_contents(&mut clear, &mut luks);
    }
    let encryption = match (clear.is_empty(), luks.is_empty()) {
        (true, false) => Check::new(ENCRYPTION, Status::Pass, format!("LUKS2: {}", luks.join(", "))),
        (true, true) => Check::new(ENCRYPTION, Status::Fail, "no fixed disk found"),
        (false, _) => Check::new(ENCRYPTION, Status::Fail, format!("not encrypted: {}", clear.join("; "))),
    };
    if luks.is_empty() {
        return vec![
            encryption,
            Check::new(RECOVERY, Status::Fail, "no LUKS2 device"),
            Check::new(TANG, Status::Fail, "no LUKS2 device"),
        ];
    }
    let recovery =
        luks.iter().map(
            |device| match stdout_of("cryptsetup", &["luksDump", "--dump-json-metadata", device]) {
                Ok(metadata) => recovery_keyslot(device, &metadata),
                Err(e) => Check::new(RECOVERY, Status::Unknown, e),
            },
        );
    let recovery = combined(RECOVERY, recovery.collect());
    let tang = luks
        .iter()
        .map(|device| match stdout_of("clevis", &["luks", "list", "-d", device]) {
            Ok(bindings) => tang_binding(device, &bindings, tang_url),
            Err(e) => Check::new(TANG, Status::Unknown, e),
        });
    let tang = combined(TANG, tang.collect());
    vec![encryption, recovery, tang]
}

/// One check over several devices: the worst status, every detail.
fn combined(name: &str, checks: Vec<Check>) -> Check {
    let status = if checks.iter().any(|check| check.status == Status::Fail) {
        Status::Fail
    } else if checks.iter().any(|check| check.status == Status::Unknown) {
        Status::Unknown
    } else {
        Status::Pass
    };
    let details: Vec<&str> = checks.iter().map(|check| check.detail.as_str()).collect();
    Check::new(name, status, details.join("; "))
}

#[derive(Deserialize)]
struct Lsblk {
    blockdevices: Vec<Device>,
}

#[derive(Deserialize)]
struct Device {
    name: String,
    path: String,
    #[serde(rename = "type")]
    kind: String,
    fstype: Option<String>,
    fsver: Option<String>,
    rm: bool,
    tran: Option<String>,
    parttype: Option<String>,
    #[serde(default)]
    mountpoints: Vec<Option<String>>,
    #[serde(default)]
    children: Vec<Device>,
}

impl Device {
    /// USB drives, card readers and optical drives come and go; zram is swap in memory.
    fn is_fixed_disk(&self) -> bool {
        self.kind == "disk" && !self.rm && self.tran.as_deref() != Some("usb") && !self.name.starts_with("zram")
    }

    /// Anything with a signature (filesystem, swap, LVM, RAID) must be LUKS2 or sit on it. Exceptions: the EFI system
    /// partition, which the firmware reads, and `/boot`, kept outside LUKS by design. Empty partitions do not matter.
    fn sort_contents(&self, clear: &mut Vec<String>, luks: &mut Vec<String>) {
        let mounted: Vec<&str> = self.mountpoints.iter().flatten().map(String::as_str).collect();
        match self.fstype.as_deref() {
            None => self.children.iter().for_each(|child| child.sort_contents(clear, luks)),
            Some("crypto_LUKS") if self.fsver.as_deref() == Some("2") => luks.push(self.path.clone()),
            Some("crypto_LUKS") => clear.push(format!("{} LUKS1", self.path)),
            Some("vfat")
                if self
                    .parttype
                    .as_deref()
                    .is_some_and(|t| ESP_PARTITION_TYPES.contains(&t)) => {}
            Some(_) if mounted == ["/boot"] => {}
            Some(fstype) if mounted.is_empty() => clear.push(format!("{} {fstype}", self.path)),
            Some(fstype) => clear.push(format!("{} {fstype} ({})", self.path, mounted.join(", "))),
        }
    }
}

#[derive(Deserialize)]
struct Metadata {
    keyslots: BTreeMap<String, serde_json::Value>,
    tokens: BTreeMap<String, Token>,
}

#[derive(Deserialize)]
struct Token {
    #[serde(rename = "type")]
    kind: String,
    keyslots: Vec<String>,
}

/// The recovery passphrase is a keyslot that Clevis does not use.
fn recovery_keyslot(device: &str, metadata: &str) -> Check {
    let metadata: Metadata = match serde_json::from_str(metadata) {
        Ok(metadata) => metadata,
        Err(e) => return Check::new(RECOVERY, Status::Unknown, format!("{device}: LUKS2 metadata: {e}")),
    };
    let clevis: BTreeSet<&String> = metadata
        .tokens
        .values()
        .filter(|t| t.kind == "clevis")
        .flat_map(|t| &t.keyslots)
        .collect();
    let passphrases: Vec<&String> = metadata.keyslots.keys().filter(|slot| !clevis.contains(slot)).collect();
    let detail = format!("{device}: passphrase keyslots {passphrases:?}, Clevis keyslots {clevis:?}");
    match passphrases.is_empty() {
        true => Check::new(RECOVERY, Status::Fail, detail),
        false => Check::new(RECOVERY, Status::Pass, detail),
    }
}

/// `clevis luks list` prints one binding per line: `1: tang '{"url":"http://tang.example"}'`.
fn tang_binding(device: &str, bindings: &str, tang_url: &str) -> Check {
    let bound = bindings.lines().any(|line| {
        let config = line
            .split_once(": tang '")
            .and_then(|(_, rest)| rest.strip_suffix('\''));
        config
            .and_then(|config| serde_json::from_str::<serde_json::Value>(config).ok())
            .is_some_and(|config| {
                config["url"].as_str().map(|url| url.trim_end_matches('/')) == Some(tang_url.trim_end_matches('/'))
            })
    });
    let detail = format!("{device}: {}", bindings.trim().replace('\n', "; "));
    match bound {
        true => Check::new(TANG, Status::Pass, detail),
        false => Check::new(TANG, Status::Fail, format!("no binding to {tang_url}; {detail}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const METADATA: &str = r#"{
        "keyslots": {"0": {"type": "luks2"}, "1": {"type": "luks2"}},
        "tokens": {"0": {"type": "clevis", "keyslots": ["1"], "jwe": {}}},
        "segments": {}, "digests": {}, "config": {}
    }"#;

    #[test]
    fn every_fixed_disk_must_be_encrypted() {
        let part = |path: &str, fstype: Option<&str>, parttype: &str, mountpoint: Option<&str>| {
            serde_json::json!({"name": path, "path": path, "type": "part", "fstype": fstype, "fsver": "2", "rm": false,
                "tran": "nvme", "parttype": parttype, "mountpoints": [mountpoint]})
        };
        let disk = |path: &str, tran: &str, children: Vec<serde_json::Value>| {
            serde_json::json!({"name": path, "path": path, "type": "disk", "fstype": null, "fsver": null, "rm": false,
                "tran": tran, "parttype": null, "mountpoints": [null], "children": children})
        };
        let tree = serde_json::json!({"blockdevices": [
            disk("/dev/nvme0n1", "nvme", vec![
                part("/dev/nvme0n1p1", Some("vfat"), "c12a7328-f81f-11d2-ba4b-00a0c93ec93b", Some("/boot/efi")),
                part("/dev/nvme0n1p2", Some("ext4"), "linux", Some("/boot")),
                part("/dev/nvme0n1p3", Some("crypto_LUKS"), "linux", None),
                part("/dev/nvme0n1p4", Some("swap"), "swap", Some("[SWAP]")),
                part("/dev/nvme0n1p5", None, "linux", None),
            ]),
            disk("/dev/sda", "sata", vec![part("/dev/sda1", Some("ext4"), "linux", Some("/mnt/data"))]),
            disk("/dev/sdb", "usb", vec![part("/dev/sdb1", Some("exfat"), "linux", Some("/media/key"))]),
        ]});
        let tree: Lsblk = serde_json::from_value(tree).unwrap();
        let (mut clear, mut luks) = (Vec::new(), Vec::new());
        for disk in tree.blockdevices.iter().filter(|device| device.is_fixed_disk()) {
            disk.sort_contents(&mut clear, &mut luks);
        }
        assert_eq!(luks, ["/dev/nvme0n1p3"]);
        assert_eq!(clear, ["/dev/nvme0n1p4 swap ([SWAP])", "/dev/sda1 ext4 (/mnt/data)"]);
    }

    #[test]
    fn a_keyslot_outside_clevis_is_the_recovery_one() {
        assert_eq!(recovery_keyslot("/dev/x", METADATA).status, Status::Pass);
        let only_clevis = METADATA.replace(r#""0": {"type": "luks2"}, "#, "");
        assert_eq!(recovery_keyslot("/dev/x", &only_clevis).status, Status::Fail);
    }

    #[test]
    fn tang_binding_must_point_to_our_server() {
        let bindings = "1: tang '{\"url\":\"http://tang.office.opfa.net\"}'\n";
        assert_eq!(
            tang_binding("/dev/x", bindings, "http://tang.office.opfa.net").status,
            Status::Pass
        );
        assert_eq!(
            tang_binding("/dev/x", bindings, "http://tang.elsewhere").status,
            Status::Fail
        );
        assert_eq!(
            tang_binding("/dev/x", "", "http://tang.office.opfa.net").status,
            Status::Fail
        );
    }
}
