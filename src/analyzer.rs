use crate::model::{
    DockerMapping, ExposureStatus, FirewallDecision, FirewallSignal, Listener, PortFinding,
};

pub fn analyze(
    listeners: Vec<Listener>,
    firewall_signals: Vec<FirewallSignal>,
    docker_mappings: Vec<DockerMapping>,
) -> Vec<PortFinding> {
    let mut findings: Vec<PortFinding> = listeners
        .into_iter()
        .map(|listener| analyze_listener(listener, &firewall_signals, &docker_mappings))
        .collect();

    for mapping in docker_mappings {
        let Some(host_port) = mapping.host_port else {
            findings.push(analyze_container_only_mapping(mapping));
            continue;
        };
        let already_reported = findings
            .iter()
            .any(|finding| finding.port == host_port && finding.protocol == mapping.protocol);
        if !already_reported {
            findings.push(analyze_docker_mapping(mapping, &firewall_signals));
        }
    }

    findings.sort_by_key(|finding| (finding.port, format!("{:?}", finding.protocol)));
    findings
}

fn analyze_listener(
    listener: Listener,
    firewall_signals: &[FirewallSignal],
    docker_mappings: &[DockerMapping],
) -> PortFinding {
    let docker = docker_mappings
        .iter()
        .find(|mapping| {
            mapping.host_port == Some(listener.port) && mapping.protocol == listener.protocol
        })
        .cloned();
    let local_only = is_loopback_bind(&listener.local_address);
    let wildcard = matches!(listener.local_address.as_str(), "0.0.0.0" | "::" | "*");
    let blocking_signal = firewall_signals
        .iter()
        .find(|signal| is_blocking_signal(signal) && signal_matches_listener(signal, &listener));
    let accept_signal = firewall_signals.iter().find(|signal| {
        signal.decision == FirewallDecision::Accept && signal_matches_listener(signal, &listener)
    });
    let guards = guards_for_listener(firewall_signals, &listener);

    let (status, firewall, mut evidence) = if local_only {
        (
            ExposureStatus::LocalOnly,
            "N/A".to_string(),
            vec![format!(
                "bind address {} is loopback",
                listener.local_address
            )],
        )
    } else if let (Some(accept), Some(block)) = (accept_signal, blocking_signal)
        && is_guard_block(block)
    {
        (
            ExposureStatus::Guarded,
            format_conflicting_sources(accept, block),
            vec![
                format!("accept signal: {}", accept.detail),
                format!("guard signal: {}", block.detail),
                "port is accepted, with conditional source blocking detected".to_string(),
            ],
        )
    } else if let (Some(accept), Some(block)) = (accept_signal, blocking_signal) {
        (
            ExposureStatus::NeedsReview,
            format_conflicting_sources(accept, block),
            vec![
                format!("accept signal: {}", accept.detail),
                format!("blocking signal: {}", block.detail),
                "conflicting firewall signals require rule-order interpretation".to_string(),
            ],
        )
    } else if let Some(signal) = accept_signal
        && !guards.is_empty()
    {
        (
            ExposureStatus::Guarded,
            format!("{:?}", signal.source),
            vec![
                signal.detail.clone(),
                "global guard chain detected before or alongside input firewall rules".to_string(),
            ],
        )
    } else if let Some(signal) = blocking_signal {
        (
            ExposureStatus::Firewalled,
            format!("{:?}", signal.source),
            vec![signal.detail.clone()],
        )
    } else if docker.is_some() {
        (
            ExposureStatus::DockerPublished,
            firewall_summary(firewall_signals),
            vec!["published by Docker".to_string()],
        )
    } else if let Some(signal) = accept_signal {
        (
            ExposureStatus::Exposed,
            format!("{:?}", signal.source),
            vec![signal.detail.clone()],
        )
    } else if wildcard {
        (
            ExposureStatus::NeedsReview,
            firewall_summary(firewall_signals),
            vec!["wildcard bind requires firewall interpretation".to_string()],
        )
    } else {
        (
            ExposureStatus::Exposed,
            firewall_summary(firewall_signals),
            vec![format!(
                "bind address {} is non-loopback",
                listener.local_address
            )],
        )
    };

    if firewall == "unknown" {
        evidence.push("firewall rules were not conclusively parsed yet".to_string());
    }

    PortFinding {
        protocol: listener.protocol,
        port: listener.port,
        process: listener.process,
        pid: listener.pid,
        listen: listener.local_address,
        firewall,
        docker,
        status,
        guards,
        evidence,
    }
}

fn analyze_docker_mapping(
    mapping: DockerMapping,
    firewall_signals: &[FirewallSignal],
) -> PortFinding {
    let host_port = mapping
        .host_port
        .expect("published Docker mapping must have a host port");
    let listener = Listener {
        protocol: mapping.protocol,
        local_address: mapping.host_ip.clone().unwrap_or_else(|| "*".to_string()),
        port: host_port,
        process: Some("docker".to_string()),
        pid: None,
    };
    let blocking_signal = firewall_signals
        .iter()
        .find(|signal| is_blocking_signal(signal) && signal_matches_listener(signal, &listener));
    let accept_signal = firewall_signals.iter().find(|signal| {
        signal.decision == FirewallDecision::Accept && signal_matches_listener(signal, &listener)
    });
    let guards = guards_for_listener(firewall_signals, &listener);

    let (status, firewall, mut evidence) = if is_loopback_bind(&listener.local_address) {
        (
            ExposureStatus::LocalOnly,
            "N/A".to_string(),
            vec![format!(
                "Docker publishes host port on loopback address {}",
                listener.local_address
            )],
        )
    } else if let (Some(accept), Some(block)) = (accept_signal, blocking_signal)
        && is_guard_block(block)
    {
        (
            ExposureStatus::Guarded,
            format_conflicting_sources(accept, block),
            vec![
                format!(
                    "Docker publishes host port for container {}",
                    mapping.container
                ),
                format!("accept signal: {}", accept.detail),
                format!("guard signal: {}", block.detail),
                "port is accepted, with conditional source blocking detected".to_string(),
            ],
        )
    } else if let (Some(accept), Some(block)) = (accept_signal, blocking_signal) {
        (
            ExposureStatus::NeedsReview,
            format_conflicting_sources(accept, block),
            vec![
                format!(
                    "Docker publishes host port for container {}",
                    mapping.container
                ),
                format!("accept signal: {}", accept.detail),
                format!("blocking signal: {}", block.detail),
                "conflicting firewall signals require rule-order interpretation".to_string(),
            ],
        )
    } else if let Some(signal) = blocking_signal {
        (
            ExposureStatus::Firewalled,
            format!("{:?}", signal.source),
            vec![
                format!(
                    "Docker publishes host port for container {}",
                    mapping.container
                ),
                signal.detail.clone(),
            ],
        )
    } else {
        (
            ExposureStatus::DockerPublished,
            firewall_summary(firewall_signals),
            vec![format!(
                "Docker publishes host port for container {}; no matching ss listener was found",
                mapping.container
            )],
        )
    };

    if firewall == "unknown" {
        evidence.push("firewall rules were not conclusively parsed yet".to_string());
    }

    PortFinding {
        protocol: mapping.protocol,
        port: host_port,
        process: Some("docker".to_string()),
        pid: None,
        listen: mapping.host_ip.clone().unwrap_or_else(|| "*".to_string()),
        firewall,
        docker: Some(mapping),
        status,
        guards,
        evidence,
    }
}

fn analyze_container_only_mapping(mapping: DockerMapping) -> PortFinding {
    PortFinding {
        protocol: mapping.protocol,
        port: mapping.container_port,
        process: Some("docker".to_string()),
        pid: None,
        listen: "container".to_string(),
        firewall: "N/A".to_string(),
        docker: Some(mapping.clone()),
        status: ExposureStatus::ContainerOnly,
        guards: Vec::new(),
        evidence: vec![format!(
            "container {} exposes this port internally but Docker does not publish it on the host",
            mapping.container
        )],
    }
}

fn signal_matches_listener(signal: &FirewallSignal, listener: &Listener) -> bool {
    signal.port == Some(listener.port)
        && signal
            .protocol
            .is_none_or(|protocol| protocol == listener.protocol)
}

fn format_conflicting_sources(accept: &FirewallSignal, block: &FirewallSignal) -> String {
    if accept.source == block.source {
        format!("{:?}", accept.source)
    } else {
        format!("{:?}+{:?}", accept.source, block.source)
    }
}

fn guards_for_listener(signals: &[FirewallSignal], listener: &Listener) -> Vec<String> {
    let mut guards: Vec<String> = signals
        .iter()
        .filter(|signal| {
            signal.guard.is_some()
                && (signal.port.is_none() || signal_matches_listener(signal, listener))
        })
        .filter_map(|signal| signal.guard.clone())
        .collect();
    guards.sort();
    guards.dedup();
    guards
}

fn is_guard_block(signal: &FirewallSignal) -> bool {
    signal.guard.is_some() || signal.conditional
}

fn is_blocking_signal(signal: &FirewallSignal) -> bool {
    matches!(
        signal.decision,
        FirewallDecision::Drop | FirewallDecision::Reject
    )
}

fn is_loopback_bind(address: &str) -> bool {
    let address = address.split('%').next().unwrap_or(address);
    address == "localhost" || address == "::1" || address.starts_with("127.")
}

fn firewall_summary(signals: &[FirewallSignal]) -> String {
    let available: Vec<String> = signals
        .iter()
        .filter(|signal| signal.decision == FirewallDecision::Present)
        .map(|signal| format!("{:?}", signal.source))
        .collect();

    if available.is_empty() {
        "unknown".to_string()
    } else {
        available.join("+")
    }
}

#[cfg(test)]
mod tests {
    use crate::model::Protocol;

    use super::*;

    #[test]
    fn loopback_is_local_only() {
        let findings = analyze(
            vec![Listener {
                protocol: Protocol::Tcp,
                local_address: "127.0.0.1".to_string(),
                port: 6379,
                process: Some("redis".to_string()),
                pid: Some(10),
            }],
            Vec::new(),
            Vec::new(),
        );

        assert_eq!(findings[0].status, ExposureStatus::LocalOnly);
    }

    #[test]
    fn loopback_range_with_interface_scope_is_local_only() {
        let findings = analyze(
            vec![Listener {
                protocol: Protocol::Udp,
                local_address: "127.0.0.53%lo".to_string(),
                port: 53,
                process: None,
                pid: None,
            }],
            Vec::new(),
            Vec::new(),
        );

        assert_eq!(findings[0].status, ExposureStatus::LocalOnly);
    }

    #[test]
    fn conflicting_firewall_signals_are_ambiguous() {
        let findings = analyze(
            vec![Listener {
                protocol: Protocol::Tcp,
                local_address: "0.0.0.0".to_string(),
                port: 22,
                process: Some("sshd".to_string()),
                pid: Some(22),
            }],
            vec![
                FirewallSignal {
                    source: crate::model::FirewallSource::Nftables,
                    decision: FirewallDecision::Accept,
                    protocol: Some(Protocol::Tcp),
                    port: Some(22),
                    guard: None,
                    conditional: false,
                    detail: "tcp dport 22 accept".to_string(),
                },
                FirewallSignal {
                    source: crate::model::FirewallSource::Nftables,
                    decision: FirewallDecision::Drop,
                    protocol: Some(Protocol::Tcp),
                    port: Some(22),
                    guard: None,
                    conditional: false,
                    detail: "tcp dport 22 drop".to_string(),
                },
            ],
            Vec::new(),
        );

        assert_eq!(findings[0].status, ExposureStatus::NeedsReview);
    }

    #[test]
    fn conditional_block_with_accept_is_guarded() {
        let findings = analyze(
            vec![Listener {
                protocol: Protocol::Tcp,
                local_address: "0.0.0.0".to_string(),
                port: 22,
                process: Some("sshd".to_string()),
                pid: Some(22),
            }],
            vec![
                FirewallSignal {
                    source: crate::model::FirewallSource::Nftables,
                    decision: FirewallDecision::Accept,
                    protocol: Some(Protocol::Tcp),
                    port: Some(22),
                    guard: None,
                    conditional: false,
                    detail: "tcp dport 22 accept".to_string(),
                },
                FirewallSignal {
                    source: crate::model::FirewallSource::Nftables,
                    decision: FirewallDecision::Reject,
                    protocol: Some(Protocol::Tcp),
                    port: Some(22),
                    guard: Some("fail2ban".to_string()),
                    conditional: true,
                    detail: "tcp dport 22 ip saddr @addr-set-sshd reject".to_string(),
                },
            ],
            Vec::new(),
        );

        assert_eq!(findings[0].status, ExposureStatus::Guarded);
        assert_eq!(findings[0].guards, vec!["fail2ban"]);
    }

    #[test]
    fn docker_mapping_without_listener_is_reported() {
        let findings = analyze(
            Vec::new(),
            Vec::new(),
            vec![DockerMapping {
                host_ip: Some("0.0.0.0".to_string()),
                host_port: Some(8080),
                container_port: 80,
                protocol: Protocol::Tcp,
                container: "web".to_string(),
            }],
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].port, 8080);
        assert_eq!(findings[0].status, ExposureStatus::DockerPublished);
    }

    #[test]
    fn container_only_docker_mapping_is_reported() {
        let findings = analyze(
            Vec::new(),
            Vec::new(),
            vec![DockerMapping {
                host_ip: None,
                host_port: None,
                container_port: 5432,
                protocol: Protocol::Tcp,
                container: "postgres".to_string(),
            }],
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].port, 5432);
        assert_eq!(findings[0].status, ExposureStatus::ContainerOnly);
    }
}
