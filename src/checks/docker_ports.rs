use super::stdout_of;
use crate::report::Outcome;

/// Docker bypasses ufw on published ports: a port published on every interface is reachable from the network, whatever
/// the firewall says. Only the port mappings are reported, never the names of the containers.
pub fn check() -> Outcome {
    if !std::path::Path::new("/usr/bin/docker").exists() {
        return Ok((true, "docker not installed".into()));
    }
    match stdout_of("docker", &["ps", "--format", "{{.Ports}}"]) {
        Ok(ports) => Ok(evaluate(&ports)),
        Err(e) if e.contains("Cannot connect to the Docker daemon") => Ok((true, "docker not running".into())),
        Err(e) => Err(e),
    }
}

fn evaluate(ports: &str) -> (bool, String) {
    let exposed: Vec<&str> = ports
        .lines()
        .flat_map(|line| line.split(", "))
        .filter(|mapping| mapping.starts_with("0.0.0.0:") || mapping.starts_with(":::") || mapping.starts_with("[::]:"))
        .collect();
    match exposed.is_empty() {
        true => (true, "no port published on every interface".into()),
        false => (false, format!("published on every interface: {}", exposed.join(" "))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_ports_published_on_every_interface_fail() {
        let private = "127.0.0.1:5432->5432/tcp\n172.17.0.1:8080->80/tcp\n\n";
        assert!(evaluate(private).0);
        let exposed = "0.0.0.0:8080->80/tcp, :::8080->80/tcp\n127.0.0.1:5432->5432/tcp\n";
        assert_eq!(
            evaluate(exposed),
            (
                false,
                "published on every interface: 0.0.0.0:8080->80/tcp :::8080->80/tcp".into()
            )
        );
    }
}
