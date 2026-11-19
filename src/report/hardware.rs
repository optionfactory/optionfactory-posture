use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// What the machine is made of, from `/proc` and `/sys`: models, versions and sizes, no serial numbers.
#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Hardware {
    /// From the firmware (SMBIOS, `/sys/class/dmi/id`), as the manufacturer filled it in.
    pub vendor: String,
    pub product: String,
    /// Where some laptops have their model: `ThinkPad T14 Gen 2i`.
    pub product_version: String,
    /// The motherboard: the telling name of a desktop.
    pub board: String,
    pub bios_version: String,
    pub bios_date: String,
    /// `model name` in `/proc/cpuinfo`.
    pub cpu: String,
    /// Logical processors.
    pub cpu_threads: usize,
    /// `microcode` in `/proc/cpuinfo`: the CPU fixes the firmware or the system loaded.
    pub microcode: String,
    /// What the kernel says of each known CPU flaw (`/sys/devices/system/cpu/vulnerabilities`): `Not affected`,
    /// `Mitigation: ...` or `Vulnerable...`.
    pub cpu_vulnerabilities: BTreeMap<String, String>,
    /// `MemTotal` in `/proc/meminfo`: the installed memory less what the firmware and the kernel keep.
    pub memory_kib: u64,
    /// The display controllers on the PCI bus.
    pub gpus: Vec<Gpu>,
    /// The network cards: the interfaces with a device behind them, not the virtual ones (bridges, Docker, VPN).
    pub nics: Vec<Nic>,
}

#[derive(Serialize, Deserialize)]
pub struct Gpu {
    /// Vendor and model from `pci.ids`, or their ids (`10de:1d01`) when it does not know them.
    pub name: String,
    /// The kernel driver bound to it, empty when none.
    pub driver: String,
    /// Its own memory, when its driver tells: `amdgpu` in sysfs, `nvidia` through `nvidia-smi`. Integrated graphics
    /// share the memory of the machine.
    #[serde(default)]
    pub memory_mib: Option<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct Nic {
    /// `enp42s0`, `wlp0s20f3`.
    pub interface: String,
    /// Vendor and model from `pci.ids` or `usb.ids`, or their ids when it does not know them.
    pub name: String,
    pub driver: String,
    /// The address of the card itself, also when it shows the networks a random one.
    pub mac: String,
    pub wireless: bool,
}

impl Hardware {
    pub fn read() -> Hardware {
        let read = |path: &str| std::fs::read_to_string(path).unwrap_or_default();
        let mut hardware = Hardware::parse(&read("/proc/cpuinfo"), &read("/proc/meminfo"));
        let dmi = |name: &str| read(&format!("/sys/class/dmi/id/{name}")).trim().to_string();
        hardware.vendor = dmi("sys_vendor");
        hardware.product = dmi("product_name");
        hardware.product_version = dmi("product_version");
        hardware.board = dmi("board_name");
        hardware.bios_version = dmi("bios_version");
        hardware.bios_date = dmi("bios_date");
        hardware.cpu_vulnerabilities = std::fs::read_dir("/sys/devices/system/cpu/vulnerabilities")
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| {
                let state = std::fs::read_to_string(entry.path()).unwrap_or_default();
                (
                    entry.file_name().to_string_lossy().into_owned(),
                    state.trim().to_string(),
                )
            })
            .collect();
        let pci_ids = read("/usr/share/misc/pci.ids");
        let mut devices: Vec<_> = std::fs::read_dir("/sys/bus/pci/devices")
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| entry.path())
            .collect();
        devices.sort();
        let mut nvidia = None;
        for device in devices {
            let id = |name: &str| {
                let value = std::fs::read_to_string(device.join(name)).unwrap_or_default();
                value.trim().trim_start_matches("0x").to_string()
            };
            // PCI class 03: display controllers
            if !id("class").starts_with("03") {
                continue;
            }
            let (vendor, model) = (id("vendor"), id("device"));
            let driver = driver(&device);
            let memory_mib = match driver.as_str() {
                "amdgpu" => id("mem_info_vram_total")
                    .parse::<u64>()
                    .ok()
                    .map(|bytes| bytes / (1024 * 1024)),
                "nvidia" => nvidia
                    .get_or_insert_with(|| {
                        crate::checks::stdout_of(
                            "nvidia-smi",
                            &["--query-gpu=pci.bus_id,memory.total", "--format=csv,noheader,nounits"],
                        )
                        .map(|stdout| nvidia_memory_mib(&stdout))
                        .unwrap_or_default()
                    })
                    .get(&device.file_name().unwrap_or_default().to_string_lossy().into_owned())
                    .copied(),
                _ => None,
            };
            hardware.gpus.push(Gpu {
                name: id_name(&pci_ids, &vendor, &model).unwrap_or(format!("{vendor}:{model}")),
                driver,
                memory_mib,
            });
        }
        hardware.nics = nics(&pci_ids, &read("/usr/share/misc/usb.ids"));
        hardware
    }

    fn parse(cpuinfo: &str, meminfo: &str) -> Hardware {
        let values = |text: &'static str, source: &str| -> Vec<String> {
            source
                .lines()
                .filter_map(|line| line.split_once(':'))
                .filter(|(key, _)| key.trim() == text)
                .map(|(_, value)| value.trim().to_string())
                .collect()
        };
        Hardware {
            cpu: values("model name", cpuinfo).into_iter().next().unwrap_or_default(),
            cpu_threads: values("processor", cpuinfo).len(),
            microcode: values("microcode", cpuinfo).into_iter().next().unwrap_or_default(),
            memory_kib: values("MemTotal", meminfo)
                .first()
                .and_then(|total| total.trim_end_matches("kB").trim().parse().ok())
                .unwrap_or_default(),
            ..Hardware::default()
        }
    }
}

fn nics(pci_ids: &str, usb_ids: &str) -> Vec<Nic> {
    // sysfs has only the address the card shows; `ip` adds the permanent one when it differs
    let permanent: BTreeMap<String, String> = crate::checks::stdout_of("ip", &["-json", "link", "show"])
        .ok()
        .and_then(|stdout| serde_json::from_str::<Vec<serde_json::Value>>(&stdout).ok())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|link| {
            Some((
                link["ifname"].as_str()?.to_string(),
                link["permaddr"].as_str()?.to_string(),
            ))
        })
        .collect();
    let mut interfaces: Vec<_> = std::fs::read_dir("/sys/class/net")
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|interface| interface.join("device").exists())
        .collect();
    interfaces.sort();
    interfaces
        .into_iter()
        .map(|interface| {
            let read = |path: PathBuf| std::fs::read_to_string(path).unwrap_or_default().trim().to_string();
            let id = |path: PathBuf| read(path).trim_start_matches("0x").to_string();
            let name = interface.file_name().unwrap_or_default().to_string_lossy().into_owned();
            let device = interface.join("device");
            let subsystem = std::fs::read_link(device.join("subsystem")).unwrap_or_default();
            let model = match subsystem.file_name().and_then(|name| name.to_str()) {
                Some("pci") => {
                    let (vendor, model) = (id(device.join("vendor")), id(device.join("device")));
                    id_name(pci_ids, &vendor, &model).unwrap_or(format!("{vendor}:{model}"))
                }
                Some("usb") => {
                    // the device is an interface of the USB device above it, which has the ids
                    let usb = device.canonicalize().unwrap_or_default().join("..");
                    let (vendor, model) = (id(usb.join("idVendor")), id(usb.join("idProduct")));
                    id_name(usb_ids, &vendor, &model).unwrap_or(format!("{vendor}:{model}"))
                }
                _ => String::new(),
            };
            Nic {
                mac: permanent
                    .get(&name)
                    .cloned()
                    .unwrap_or_else(|| read(interface.join("address"))),
                wireless: interface.join("wireless").exists() || interface.join("phy80211").exists(),
                driver: driver(&device),
                name: model,
                interface: name,
            }
        })
        .collect()
}

fn driver(device: &Path) -> String {
    std::fs::read_link(device.join("driver"))
        .ok()
        .and_then(|driver| Some(driver.file_name()?.to_string_lossy().into_owned()))
        .unwrap_or_default()
}

/// The memory of each NVIDIA card by its PCI address as sysfs writes it: `nvidia-smi` prints `00000000:2B:00.0, 2048`.
fn nvidia_memory_mib(stdout: &str) -> BTreeMap<String, u64> {
    stdout
        .lines()
        .filter_map(|line| line.split_once(','))
        .filter_map(|(bus, mib)| {
            let bus = bus.trim().to_ascii_lowercase();
            Some((
                bus.get(bus.len().checked_sub(12)?..)?.to_string(),
                mib.trim().parse().ok()?,
            ))
        })
        .collect()
}

/// `pci.ids` and `usb.ids`: a vendor line `10de  NVIDIA Corporation`, then its devices indented by a tab, their
/// subsystems or interfaces by two.
fn id_name(ids: &str, vendor: &str, device: &str) -> Option<String> {
    let mut lines = ids.lines().skip_while(|line| !line.starts_with(&format!("{vendor}  ")));
    let vendor_name = lines.next()?.get(vendor.len()..)?.trim();
    let device_name = lines
        .take_while(|line| line.starts_with('\t') || line.starts_with('#') || line.is_empty())
        .find_map(|line| line.strip_prefix('\t')?.strip_prefix(device)?.strip_prefix("  "))?;
    Some(format!("{vendor_name} {device_name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hardware_comes_from_proc_and_pci_ids() {
        let cpuinfo = "processor\t: 0\nmodel name\t: AMD Ryzen 5 5600X 6-Core Processor\nmicrocode\t: 0xa20102e\n\n\
                       processor\t: 1\nmodel name\t: AMD Ryzen 5 5600X 6-Core Processor\nmicrocode\t: 0xa20102e\n";
        let hardware = Hardware::parse(cpuinfo, "MemTotal:       32784660 kB\nMemFree: 1 kB\n");
        let pci_ids = "# comment\n10de  NVIDIA Corporation\n\t1d01  GP108 [GeForce GT 1030]\n\
                       \t\t1043 85f4  GeForce GT 1030\n10df  Emulex Corporation\n\t1d02  Other\n";

        assert_eq!(
            (
                hardware.cpu.as_str(),
                hardware.cpu_threads,
                hardware.microcode.as_str(),
                hardware.memory_kib
            ),
            ("AMD Ryzen 5 5600X 6-Core Processor", 2, "0xa20102e", 32784660)
        );
        assert_eq!(
            id_name(pci_ids, "10de", "1d01").as_deref(),
            Some("NVIDIA Corporation GP108 [GeForce GT 1030]")
        );
        assert_eq!(id_name(pci_ids, "10de", "1d02"), None);
        assert_eq!(
            nvidia_memory_mib("00000000:2B:00.0, 2048\n00000000:01:00.0, [N/A]\n"),
            BTreeMap::from([("0000:2b:00.0".to_string(), 2048)])
        );
    }
}
