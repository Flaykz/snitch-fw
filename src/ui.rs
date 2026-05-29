use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap};

use crate::model::{ExposureStatus, PortFinding};

#[derive(Debug, Clone)]
struct DisplayFinding {
    process: String,
    protocol: String,
    listen: String,
    port: u16,
    status: ExposureStatus,
    firewall: String,
    guard: String,
    docker: String,
    evidence: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ViewMode {
    Global,
    All,
    Local,
    Container,
}

pub fn run<F>(mut load_findings: F, refresh: Duration, full: bool) -> Result<()>
where
    F: FnMut() -> Result<Vec<PortFinding>>,
{
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let result = run_loop(&mut terminal, &mut load_findings, refresh, full);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    load_findings: &mut impl FnMut() -> Result<Vec<PortFinding>>,
    refresh: Duration,
    full: bool,
) -> Result<()> {
    let mut findings = load_findings()?;
    let mut selected = 0usize;
    let mut view_mode = ViewMode::Global;
    let mut last_tick = Instant::now();
    loop {
        let display_findings = display_findings(&findings, full, view_mode);
        if selected >= display_findings.len() {
            selected = display_findings.len().saturating_sub(1);
        }

        terminal.draw(|frame| {
            let [table_area, details_area] =
                Layout::vertical([Constraint::Min(0), Constraint::Length(8)]).areas(frame.area());
            let rows = display_findings.iter().enumerate().map(|(index, finding)| {
                let style = if index == selected {
                    status_style(finding.status).add_modifier(Modifier::REVERSED)
                } else {
                    status_style(finding.status)
                };

                Row::new(vec![
                    Cell::from(finding.process.clone()),
                    Cell::from(finding.protocol.clone()),
                    Cell::from(finding.listen.clone()),
                    Cell::from(finding.port.to_string()),
                    Cell::from(format_status(finding.status)),
                    Cell::from(finding.firewall.clone()),
                    Cell::from(finding.guard.clone()),
                    Cell::from(finding.docker.clone()),
                ])
                .style(style)
            });

            let table = Table::new(
                rows,
                [
                    Constraint::Length(18),
                    Constraint::Length(7),
                    Constraint::Length(18),
                    Constraint::Length(6),
                    Constraint::Length(14),
                    Constraint::Length(14),
                    Constraint::Length(16),
                    Constraint::Min(18),
                ],
            )
            .header(
                Row::new([
                    "PROCESS", "PROTO", "LISTEN", "PORT", "STATUS", "FIREWALL", "GUARD", "DOCKER",
                ])
                .style(Style::new().fg(Color::Cyan)),
            )
            .block(
                Block::new()
                    .title(format!(
                        "snitch-fw - mode: {} | m mode | q quit | r refresh | up/down details",
                        view_mode.label()
                    ))
                    .borders(Borders::ALL),
            );

            frame.render_widget(table, table_area);

            let details = display_findings
                .get(selected)
                .map(format_details)
                .unwrap_or_else(|| "No findings".to_string());
            let details = Paragraph::new(details)
                .block(Block::new().title("details").borders(Borders::ALL))
                .wrap(Wrap { trim: false });
            frame.render_widget(details, details_area);
        })?;

        let timeout = refresh.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)?
            && let Event::Key(key) = event::read()?
        {
            if key.code == KeyCode::Char('q') || key.code == KeyCode::Esc {
                break;
            }
            if key.code == KeyCode::Char('r') {
                findings = load_findings()?;
                last_tick = Instant::now();
            }
            if key.code == KeyCode::Char('m') {
                view_mode = view_mode.next();
                selected = 0;
            }
            if key.code == KeyCode::Down || key.code == KeyCode::Char('j') {
                selected = (selected + 1).min(display_findings.len().saturating_sub(1));
            }
            if key.code == KeyCode::Up || key.code == KeyCode::Char('k') {
                selected = selected.saturating_sub(1);
            }
        }

        if last_tick.elapsed() >= refresh {
            findings = load_findings()?;
            last_tick = Instant::now();
        }
    }
    Ok(())
}

impl ViewMode {
    fn next(self) -> Self {
        match self {
            Self::Global => Self::All,
            Self::All => Self::Local,
            Self::Local => Self::Container,
            Self::Container => Self::Global,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::All => "all",
            Self::Local => "local",
            Self::Container => "container",
        }
    }
}

fn display_findings(
    findings: &[PortFinding],
    full: bool,
    view_mode: ViewMode,
) -> Vec<DisplayFinding> {
    let filtered: Vec<&PortFinding> = findings
        .iter()
        .filter(|finding| view_mode.includes(finding))
        .collect();

    if full {
        return filtered.into_iter().map(DisplayFinding::from).collect();
    }

    let mut groups: BTreeMap<(u16, String, String), Vec<&PortFinding>> = BTreeMap::new();
    for finding in filtered {
        groups.entry(group_key(finding)).or_default().push(finding);
    }

    groups
        .into_values()
        .map(|group| {
            let mut processes = BTreeSet::new();
            let mut protocols = BTreeSet::new();
            let mut firewalls = BTreeSet::new();
            let mut guards = BTreeSet::new();
            let mut dockers = BTreeSet::new();
            let mut listeners = BTreeSet::new();
            let mut evidence = Vec::new();
            let mut status = ExposureStatus::LocalOnly;

            for finding in &group {
                processes.insert(finding.process.clone().unwrap_or_else(|| "-".to_string()));
                protocols.insert(format!("{:?}", finding.protocol).to_lowercase());
                firewalls.insert(finding.firewall.clone());
                guards.extend(finding.guards.iter().cloned());
                listeners.insert(finding.listen.clone());
                if let Some(docker) = &finding.docker {
                    dockers.insert(short_docker_name(&docker.container));
                }
                evidence.extend(finding.evidence.clone());
                status = worst_status(status, finding.status);
            }

            let first = group[0];
            if listeners.len() > 1 {
                evidence.push(format!("listeners: {}", join_set(listeners.clone())));
            }
            DisplayFinding {
                process: join_set(processes),
                protocol: join_set(protocols),
                listen: preferred_listen(&listeners).unwrap_or_else(|| first.listen.clone()),
                port: first.port,
                status,
                firewall: join_set(firewalls),
                guard: if guards.is_empty() {
                    "-".to_string()
                } else {
                    join_set(guards)
                },
                docker: if dockers.is_empty() {
                    "-".to_string()
                } else {
                    join_set(dockers)
                },
                evidence,
            }
        })
        .collect()
}

impl ViewMode {
    fn includes(self, finding: &PortFinding) -> bool {
        match self {
            Self::Global => !matches!(
                finding.status,
                ExposureStatus::LocalOnly | ExposureStatus::ContainerOnly
            ),
            Self::All => true,
            Self::Local => finding.status == ExposureStatus::LocalOnly,
            Self::Container => finding.status == ExposureStatus::ContainerOnly,
        }
    }
}

fn group_key(finding: &PortFinding) -> (u16, String, String) {
    let process = finding.process.clone().unwrap_or_else(|| "-".to_string());
    if is_wildcard_listen(&finding.listen) {
        (finding.port, process, "wildcard".to_string())
    } else {
        (finding.port, process, finding.listen.clone())
    }
}

fn is_wildcard_listen(listen: &str) -> bool {
    matches!(listen, "0.0.0.0" | "::" | "*")
}

fn preferred_listen(listeners: &BTreeSet<String>) -> Option<String> {
    for candidate in ["0.0.0.0", "*", "::"] {
        if listeners.contains(candidate) {
            return Some(candidate.to_string());
        }
    }
    listeners.iter().next().cloned()
}

impl From<&PortFinding> for DisplayFinding {
    fn from(finding: &PortFinding) -> Self {
        Self {
            process: finding.process.clone().unwrap_or_else(|| "-".to_string()),
            protocol: format!("{:?}", finding.protocol).to_lowercase(),
            listen: finding.listen.clone(),
            port: finding.port,
            status: finding.status,
            firewall: finding.firewall.clone(),
            guard: if finding.guards.is_empty() {
                "-".to_string()
            } else {
                finding.guards.join(",")
            },
            docker: finding
                .docker
                .as_ref()
                .map(|docker| short_docker_name(&docker.container))
                .unwrap_or_else(|| "-".to_string()),
            evidence: finding.evidence.clone(),
        }
    }
}

fn short_docker_name(name: &str) -> String {
    if let Some((service, _)) = name.split_once(".1.") {
        service.to_string()
    } else {
        name.to_string()
    }
}

fn join_set(values: BTreeSet<String>) -> String {
    values.into_iter().collect::<Vec<_>>().join(",")
}

fn worst_status(left: ExposureStatus, right: ExposureStatus) -> ExposureStatus {
    if status_rank(right) > status_rank(left) {
        right
    } else {
        left
    }
}

fn status_rank(status: ExposureStatus) -> u8 {
    match status {
        ExposureStatus::Exposed => 6,
        ExposureStatus::Guarded => 5,
        ExposureStatus::NeedsReview => 4,
        ExposureStatus::DockerPublished => 3,
        ExposureStatus::Firewalled => 2,
        ExposureStatus::ContainerOnly => 1,
        ExposureStatus::LocalOnly => 0,
    }
}

fn format_details(finding: &DisplayFinding) -> String {
    let evidence = if finding.evidence.is_empty() {
        "-".to_string()
    } else {
        finding.evidence.join("\n")
    };

    format!(
        "process: {} | proto: {} | listen: {} | port: {} | status: {}\nfirewall: {}\nguard: {}\ndocker: {}\nevidence:\n{}",
        finding.process,
        finding.protocol,
        finding.listen,
        finding.port,
        format_status(finding.status),
        finding.firewall,
        finding.guard,
        finding.docker,
        evidence
    )
}

fn format_status(status: ExposureStatus) -> &'static str {
    match status {
        ExposureStatus::LocalOnly => "local only",
        ExposureStatus::Exposed => "exposed",
        ExposureStatus::Firewalled => "firewalled",
        ExposureStatus::DockerPublished => "docker published",
        ExposureStatus::ContainerOnly => "container only",
        ExposureStatus::Guarded => "guarded",
        ExposureStatus::NeedsReview => "needs review",
    }
}

fn status_style(status: ExposureStatus) -> Style {
    match status {
        ExposureStatus::LocalOnly => Style::new().fg(Color::Green),
        ExposureStatus::ContainerOnly => Style::new().fg(Color::Green),
        ExposureStatus::Firewalled => Style::new().fg(Color::Blue),
        ExposureStatus::Guarded => Style::new().fg(Color::LightYellow),
        ExposureStatus::DockerPublished | ExposureStatus::NeedsReview => {
            Style::new().fg(Color::Yellow)
        }
        ExposureStatus::Exposed => Style::new().fg(Color::Red),
    }
}
