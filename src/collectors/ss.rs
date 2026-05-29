use std::process::Command;

use anyhow::{Context, Result};

use crate::model::{Listener, Protocol};

pub fn collect_listeners() -> Result<Vec<Listener>> {
    let output = Command::new("ss")
        .args(["-H", "-tulpen"])
        .output()
        .context("failed to execute ss; is iproute2 installed?")?;

    if !output.status.success() {
        anyhow::bail!("ss failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_ss_output(&stdout))
}

pub fn parse_ss_output(output: &str) -> Vec<Listener> {
    output.lines().filter_map(parse_line).collect()
}

fn parse_line(line: &str) -> Option<Listener> {
    let columns: Vec<&str> = line.split_whitespace().collect();
    if columns.len() < 5 {
        return None;
    }

    let protocol = match columns[0] {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        _ => return None,
    };

    let local = columns[4];
    let (local_address, port) = parse_socket(local)?;
    let tail = columns.get(5..).unwrap_or_default().join(" ");
    let process = parse_process_name(&tail);
    let pid = parse_pid(&tail);

    Some(Listener {
        protocol,
        local_address,
        port,
        process,
        pid,
    })
}

fn parse_socket(socket: &str) -> Option<(String, u16)> {
    let normalized = socket.trim_matches('"');
    let (address, port) = normalized.rsplit_once(':')?;
    let port = port.parse().ok()?;
    let address = address.trim_start_matches('[').trim_end_matches(']');
    Some((address.to_string(), port))
}

fn parse_process_name(text: &str) -> Option<String> {
    let start = text.find("users:((\"")? + "users:((\"".len();
    let rest = &text[start..];
    let end = rest.find('\"')?;
    Some(rest[..end].to_string())
}

fn parse_pid(text: &str) -> Option<u32> {
    let start = text.find("pid=")? + "pid=".len();
    let rest = &text[start..];
    let end = rest.find(',').unwrap_or(rest.len());
    rest[..end].parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tcp_listener() {
        let out = r#"tcp LISTEN 0 4096 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=42,fd=7))"#;

        let listeners = parse_ss_output(out);

        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].protocol, Protocol::Tcp);
        assert_eq!(listeners[0].local_address, "0.0.0.0");
        assert_eq!(listeners[0].port, 80);
        assert_eq!(listeners[0].process.as_deref(), Some("nginx"));
        assert_eq!(listeners[0].pid, Some(42));
    }

    #[test]
    fn parses_ipv6_listener() {
        let out = r#"tcp LISTEN 0 4096 [::]:443 [::]:* users:(("nginx",pid=43,fd=8))"#;

        let listeners = parse_ss_output(out);

        assert_eq!(listeners[0].local_address, "::");
        assert_eq!(listeners[0].port, 443);
    }
}
