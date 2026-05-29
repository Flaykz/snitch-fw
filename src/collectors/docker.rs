use std::process::Command;

use crate::model::{DockerMapping, Protocol};

pub fn collect_docker_mappings() -> Vec<DockerMapping> {
    let Ok(output) = Command::new("docker")
        .args(["ps", "--format", "{{json .}}"])
        .output()
    else {
        return Vec::new();
    };

    if !output.status.success() {
        return Vec::new();
    }

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .flat_map(parse_docker_line)
        .collect()
}

fn parse_docker_line(line: &str) -> Vec<DockerMapping> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
        return Vec::new();
    };
    let container = value
        .get("Names")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let ports = value
        .get("Ports")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    ports
        .split(',')
        .filter_map(|entry| parse_port_mapping(entry.trim(), &container))
        .collect()
}

fn parse_port_mapping(entry: &str, container: &str) -> Option<DockerMapping> {
    let (host_ip, host_port, container_port) =
        if let Some((host, container_port)) = entry.split_once("->") {
            let (host_ip, host_port) = host.rsplit_once(':')?;
            (
                Some(host_ip.to_string()),
                Some(host_port.parse().ok()?),
                container_port,
            )
        } else {
            (None, None, entry)
        };
    let (container_port, protocol) = parse_container_port(container_port)?;

    Some(DockerMapping {
        host_ip,
        host_port,
        container_port,
        protocol,
        container: container.to_string(),
    })
}

fn parse_container_port(container_port: &str) -> Option<(u16, Protocol)> {
    let (port, protocol) = container_port.rsplit_once('/')?;
    let protocol = if protocol == "tcp" {
        Protocol::Tcp
    } else if protocol == "udp" {
        Protocol::Udp
    } else {
        return None;
    };
    Some((port.parse().ok()?, protocol))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_docker_mapping() {
        let line = r#"{"Names":"web","Ports":"0.0.0.0:8080->80/tcp"}"#;

        let mappings = parse_docker_line(line);

        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].host_port, Some(8080));
        assert_eq!(mappings[0].container_port, 80);
        assert_eq!(mappings[0].protocol, Protocol::Tcp);
        assert_eq!(mappings[0].container, "web");
    }

    #[test]
    fn parses_multiple_docker_mappings() {
        let line = r#"{"Names":"dns","Ports":"0.0.0.0:53->53/udp, 0.0.0.0:5353->53/tcp"}"#;

        let mappings = parse_docker_line(line);

        assert_eq!(mappings.len(), 2);
        assert_eq!(mappings[0].host_port, Some(53));
        assert_eq!(mappings[0].protocol, Protocol::Udp);
        assert_eq!(mappings[1].host_port, Some(5353));
        assert_eq!(mappings[1].protocol, Protocol::Tcp);
    }

    #[test]
    fn parses_container_only_port() {
        let line = r#"{"Names":"db","Ports":"5432/tcp"}"#;

        let mappings = parse_docker_line(line);

        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].host_port, None);
        assert_eq!(mappings[0].container_port, 5432);
        assert_eq!(mappings[0].protocol, Protocol::Tcp);
    }
}
