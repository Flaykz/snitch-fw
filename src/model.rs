use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Listener {
    pub protocol: Protocol,
    pub local_address: String,
    pub port: u16,
    pub process: Option<String>,
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FirewallSignal {
    pub source: FirewallSource,
    pub decision: FirewallDecision,
    pub protocol: Option<Protocol>,
    pub port: Option<u16>,
    pub guard: Option<String>,
    pub conditional: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FirewallSource {
    Nftables,
    Iptables,
    Ufw,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FirewallDecision {
    Accept,
    Drop,
    Reject,
    Present,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DockerMapping {
    pub host_ip: Option<String>,
    pub host_port: Option<u16>,
    pub container_port: u16,
    pub protocol: Protocol,
    pub container: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExposureStatus {
    LocalOnly,
    Exposed,
    Firewalled,
    DockerPublished,
    ContainerOnly,
    Guarded,
    NeedsReview,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PortFinding {
    pub protocol: Protocol,
    pub port: u16,
    pub process: Option<String>,
    pub pid: Option<u32>,
    pub listen: String,
    pub firewall: String,
    pub docker: Option<DockerMapping>,
    pub status: ExposureStatus,
    pub guards: Vec<String>,
    pub evidence: Vec<String>,
}
