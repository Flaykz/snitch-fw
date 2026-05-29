use std::time::Duration;

use anyhow::Result;
use clap::Parser;

mod analyzer;
mod collectors;
mod model;
mod ui;

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Correlate local listeners, firewall signals and Docker published ports"
)]
struct Args {
    #[arg(long, help = "Print findings as JSON instead of opening the TUI")]
    json: bool,

    #[arg(long, help = "Skip Docker collection")]
    no_docker: bool,

    #[arg(
        long,
        help = "Hide Docker container-only ports that are not published on the host"
    )]
    host_only: bool,

    #[arg(
        long,
        help = "Show every raw finding instead of grouping by port and listen address"
    )]
    full: bool,

    #[arg(long, default_value_t = 2, help = "TUI refresh interval in seconds")]
    refresh: u64,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.json {
        let findings = collect_findings(args.no_docker, args.host_only)?;
        println!("{}", serde_json::to_string_pretty(&findings)?);
        return Ok(());
    }

    ui::run(
        || collect_findings(args.no_docker, args.host_only),
        Duration::from_secs(args.refresh.max(1)),
        args.full,
    )
}

fn collect_findings(no_docker: bool, host_only: bool) -> Result<Vec<model::PortFinding>> {
    let listeners = collectors::ss::collect_listeners()?;
    let firewall_signals = collectors::firewall::collect_firewall_signals(&listeners);
    let docker_mappings = if no_docker {
        Vec::new()
    } else {
        collectors::docker::collect_docker_mappings()
    };

    let mut findings = analyzer::analyze(listeners, firewall_signals, docker_mappings);

    if host_only {
        findings.retain(|finding| finding.status != model::ExposureStatus::ContainerOnly);
    }

    Ok(findings)
}
