use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A TCP port open to the network on the machine itself: the address and the port, never the process, which would tell
/// the applications. The firewall decides who reaches it.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Listening {
    pub address: IpAddr,
    pub port: u16,
}

/// The listening TCP sockets of `/proc/net/tcp` and `/proc/net/tcp6`, without those on loopback; `None` when they
/// cannot be read, rather than an empty list that would say nothing listens. `tcp6` is missing only with IPv6 off.
pub fn read() -> Option<Vec<Listening>> {
    let mut all = Vec::new();
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        match std::fs::read_to_string(path) {
            Ok(table) => all.extend(parse(&table)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && path.ends_with('6') => {}
            Err(_) => return None,
        }
    }
    all.retain(|listening: &Listening| !listening.address.is_loopback());
    all.sort();
    all.dedup();
    Some(all)
}

/// One socket per line after the header: `sl local_address rem_address st ...`, the local address as `<ip>:<port>` in
/// hex, the state `0A` for listening. The kernel writes the address as 32-bit words in the byte order of the machine,
/// little-endian on the amd64 the agent is built for.
fn parse(table: &str) -> Vec<Listening> {
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.get(3) != Some(&"0A") {
                return None;
            }
            let (address, port) = fields.get(1)?.split_once(':')?;
            let mut bytes = Vec::new();
            for word in 0..address.len() / 8 {
                let word = u32::from_str_radix(address.get(word * 8..word * 8 + 8)?, 16).ok()?;
                bytes.extend(word.to_le_bytes());
            }
            let address = match bytes.len() {
                4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).ok()?)),
                16 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?)),
                _ => return None,
            };
            Some(Listening {
                address,
                port: u16::from_str_radix(port, 16).ok()?,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_listening_sockets_count_with_their_address_and_port() {
        let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1\n\
                   1: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2\n\
                   2: 5A00A8C0:A3B2 0E00A8C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 3\n";
        let tcp6 = "  sl  local_address                         remote_address                        st\n\
                    0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A\n";
        let listening = |address: &str, port| Listening {
            address: address.parse().unwrap(),
            port,
        };

        assert_eq!(parse(tcp), [listening("0.0.0.0", 22), listening("127.0.0.1", 631)]);
        assert_eq!(parse(tcp6), [listening("::", 8080)]);
    }
}
