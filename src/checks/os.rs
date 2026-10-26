use crate::report::Outcome;
use serde::{Deserialize, Serialize};

/// The fields of `/etc/os-release` the review and the asset register need.
#[derive(Serialize, Deserialize, Default)]
pub struct Os {
    pub id: String,
    pub version_id: String,
    pub pretty_name: String,
}

impl Os {
    pub fn read() -> Os {
        std::fs::read_to_string("/etc/os-release")
            .map(|content| Os::parse(&content))
            .unwrap_or_default()
    }

    fn parse(content: &str) -> Os {
        let mut os = Os::default();
        for line in content.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = value.trim_matches('"').to_string();
            match key {
                "ID" => os.id = value,
                "VERSION_ID" => os.version_id = value,
                "PRETTY_NAME" => os.pretty_name = value,
                _ => {}
            }
        }
        os
    }

    /// Linux Mint 22.x, Ubuntu 24.04 LTS and Debian 13: the systems the baseline and the disk encryption support.
    pub fn check(&self) -> Outcome {
        let supported = match self.id.as_str() {
            "linuxmint" => self.version_id.split('.').next() == Some("22"),
            "ubuntu" => self.version_id == "24.04",
            "debian" => self.version_id == "13",
            _ => false,
        };
        match supported {
            true => Ok((true, self.pretty_name.clone())),
            false => Ok((false, format!("{} is not supported", self.pretty_name))),
        }
    }
}
