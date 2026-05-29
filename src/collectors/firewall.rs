use std::process::Command;

use crate::model::{FirewallDecision, FirewallSignal, FirewallSource, Listener, Protocol};

pub fn collect_firewall_signals(listeners: &[Listener]) -> Vec<FirewallSignal> {
    let mut signals = Vec::new();
    collect_nftables(&mut signals, listeners);
    collect_iptables(&mut signals, listeners);
    collect_ufw(&mut signals, listeners);
    signals
}

fn collect_nftables(signals: &mut Vec<FirewallSignal>, listeners: &[Listener]) {
    match Command::new("nft").args(["list", "ruleset"]).output() {
        Ok(output) if output.status.success() => {
            let ruleset = String::from_utf8_lossy(&output.stdout);
            let parsed = parse_nftables_ruleset(&ruleset, listeners);
            if parsed.is_empty() {
                signals.push(presence_signal(
                    FirewallSource::Nftables,
                    "nftables ruleset available, no direct port verdict parsed",
                ));
            } else {
                signals.extend(parsed);
            }
        }
        Ok(_) => signals.push(unavailable_signal(
            FirewallSource::Nftables,
            "nft command failed, often because privileges are missing",
        )),
        Err(_) => signals.push(unavailable_signal(
            FirewallSource::Nftables,
            "nft command not found",
        )),
    }
}

fn collect_iptables(signals: &mut Vec<FirewallSignal>, listeners: &[Listener]) {
    match Command::new("iptables-save").output() {
        Ok(output) if output.status.success() => {
            let rules = String::from_utf8_lossy(&output.stdout);
            let parsed = parse_iptables_save(&rules, listeners);
            if parsed.is_empty() {
                signals.push(presence_signal(
                    FirewallSource::Iptables,
                    "iptables rules available, no direct port verdict parsed",
                ));
            } else {
                signals.extend(parsed);
            }
        }
        Ok(_) => signals.push(unavailable_signal(
            FirewallSource::Iptables,
            "iptables-save failed, often because privileges are missing",
        )),
        Err(_) => signals.push(unavailable_signal(
            FirewallSource::Iptables,
            "iptables-save command not found",
        )),
    }
}

fn collect_ufw(signals: &mut Vec<FirewallSignal>, listeners: &[Listener]) {
    match Command::new("ufw").args(["status", "verbose"]).output() {
        Ok(output) if output.status.success() => {
            let status = String::from_utf8_lossy(&output.stdout);
            let parsed = parse_ufw_status(&status, listeners);
            if parsed.is_empty() {
                signals.push(presence_signal(
                    FirewallSource::Ufw,
                    status.lines().next().unwrap_or("ufw available"),
                ));
            } else {
                signals.extend(parsed);
            }
        }
        Ok(_) => signals.push(unavailable_signal(FirewallSource::Ufw, "ufw status failed")),
        Err(_) => signals.push(unavailable_signal(
            FirewallSource::Ufw,
            "ufw command not found",
        )),
    }
}

pub fn parse_iptables_save(rules: &str, listeners: &[Listener]) -> Vec<FirewallSignal> {
    rules
        .lines()
        .filter(|line| line.starts_with("-A INPUT") || line.starts_with("-A DOCKER-USER"))
        .filter_map(|line| parse_rule_line(FirewallSource::Iptables, line, listeners))
        .collect()
}

pub fn parse_nftables_ruleset(ruleset: &str, listeners: &[Listener]) -> Vec<FirewallSignal> {
    let mut signals = Vec::new();
    let mut context = String::new();

    for line in ruleset.lines().map(str::trim) {
        if line.starts_with("table ") || line.starts_with("chain ") {
            context = line.to_string();
        }

        let context_lower = context.to_ascii_lowercase();
        let line_lower = line.to_ascii_lowercase();
        if context_lower.contains("crowdsec") && has_verdict(line) {
            signals.push(guard_signal("crowdsec", line));
            continue;
        }

        if line.contains(" dport ")
            && has_verdict(line)
            && let Some(mut signal) = parse_rule_line(FirewallSource::Nftables, line, listeners)
        {
            if context_lower.contains("f2b")
                || context_lower.contains("fail2ban")
                || line_lower.contains("addr-set-")
            {
                signal.guard = Some("fail2ban".to_string());
                signal.conditional = true;
            }
            signals.push(signal);
        }
    }

    signals
}

pub fn parse_ufw_status(status: &str, listeners: &[Listener]) -> Vec<FirewallSignal> {
    status
        .lines()
        .filter_map(|line| parse_ufw_line(line.trim(), listeners))
        .collect()
}

fn parse_rule_line(
    source: FirewallSource,
    line: &str,
    listeners: &[Listener],
) -> Option<FirewallSignal> {
    let decision = parse_decision(line)?;
    let protocol = parse_protocol(line);
    let port = matching_listener_port(line, protocol, listeners)?;

    Some(FirewallSignal {
        source,
        decision,
        protocol,
        port: Some(port),
        guard: None,
        conditional: is_conditional_rule(line),
        detail: line.to_string(),
    })
}

fn parse_ufw_line(line: &str, listeners: &[Listener]) -> Option<FirewallSignal> {
    let decision = if line.contains(" ALLOW ") {
        FirewallDecision::Accept
    } else if line.contains(" DENY ") {
        FirewallDecision::Drop
    } else if line.contains(" REJECT ") {
        FirewallDecision::Reject
    } else {
        return None;
    };

    let protocol = parse_protocol(line);
    let port = matching_listener_port(line, protocol, listeners)?;

    Some(FirewallSignal {
        source: FirewallSource::Ufw,
        decision,
        protocol,
        port: Some(port),
        guard: None,
        conditional: is_conditional_rule(line),
        detail: line.to_string(),
    })
}

fn guard_signal(guard: &str, detail: &str) -> FirewallSignal {
    FirewallSignal {
        source: FirewallSource::Nftables,
        decision: FirewallDecision::Drop,
        protocol: None,
        port: None,
        guard: Some(guard.to_string()),
        conditional: true,
        detail: detail.to_string(),
    }
}

fn matching_listener_port(
    line: &str,
    protocol: Option<Protocol>,
    listeners: &[Listener],
) -> Option<u16> {
    listeners
        .iter()
        .find(|listener| {
            protocol.is_none_or(|proto| proto == listener.protocol)
                && contains_port_token(line, listener.port)
        })
        .map(|listener| listener.port)
}

fn parse_decision(line: &str) -> Option<FirewallDecision> {
    if line.contains(" -j ACCEPT") || line.ends_with(" accept") || line.contains(" accept ") {
        Some(FirewallDecision::Accept)
    } else if line.contains(" -j DROP") || line.ends_with(" drop") || line.contains(" drop ") {
        Some(FirewallDecision::Drop)
    } else if line.contains(" -j REJECT") || line.ends_with(" reject") || line.contains(" reject ")
    {
        Some(FirewallDecision::Reject)
    } else {
        None
    }
}

fn parse_protocol(line: &str) -> Option<Protocol> {
    if line.contains(" tcp ") || line.contains(" -p tcp") || line.contains("/tcp") {
        Some(Protocol::Tcp)
    } else if line.contains(" udp ") || line.contains(" -p udp") || line.contains("/udp") {
        Some(Protocol::Udp)
    } else {
        None
    }
}

fn contains_port_token(line: &str, port: u16) -> bool {
    let port = port.to_string();
    line.split(|c: char| !c.is_ascii_alphanumeric())
        .any(|token| token == port)
}

fn has_verdict(line: &str) -> bool {
    line.contains(" accept") || line.contains(" drop") || line.contains(" reject")
}

fn is_conditional_rule(line: &str) -> bool {
    line.contains(" ip saddr ")
        || line.contains(" ip6 saddr ")
        || line.contains(" @")
        || line.contains(" match \"set\"")
        || line.contains(" limit rate ")
}

fn presence_signal(source: FirewallSource, detail: &str) -> FirewallSignal {
    FirewallSignal {
        source,
        decision: FirewallDecision::Present,
        protocol: None,
        port: None,
        guard: None,
        conditional: false,
        detail: detail.to_string(),
    }
}

fn unavailable_signal(source: FirewallSource, detail: &str) -> FirewallSignal {
    FirewallSignal {
        source,
        decision: FirewallDecision::Unavailable,
        protocol: None,
        port: None,
        guard: None,
        conditional: false,
        detail: detail.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listener(port: u16) -> Listener {
        Listener {
            protocol: Protocol::Tcp,
            local_address: "0.0.0.0".to_string(),
            port,
            process: None,
            pid: None,
        }
    }

    #[test]
    fn parses_iptables_accept() {
        let signals = parse_iptables_save(
            "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT",
            &[listener(22)],
        );

        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].decision, FirewallDecision::Accept);
        assert_eq!(signals[0].port, Some(22));
    }

    #[test]
    fn parses_nft_drop() {
        let signals = parse_nftables_ruleset("tcp dport 5432 drop", &[listener(5432)]);

        assert_eq!(signals[0].decision, FirewallDecision::Drop);
        assert_eq!(signals[0].port, Some(5432));
    }

    #[test]
    fn parses_ufw_allow() {
        let signals = parse_ufw_status("22/tcp ALLOW IN Anywhere", &[listener(22)]);

        assert_eq!(signals[0].decision, FirewallDecision::Accept);
        assert_eq!(signals[0].port, Some(22));
    }
}
