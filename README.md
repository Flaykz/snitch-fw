# snitch-fw

[![CI](https://github.com/Flaykz/snitch-fw/actions/workflows/ci.yml/badge.svg)](https://github.com/Flaykz/snitch-fw/actions/workflows/ci.yml)
[![Release](https://github.com/Flaykz/snitch-fw/actions/workflows/release.yml/badge.svg)](https://github.com/Flaykz/snitch-fw/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`snitch-fw` is a Linux host TUI that correlates listening sockets with local firewall and Docker signals.

It is intentionally conservative: when firewall rules cannot be interpreted conclusively, the status is `ambiguous` instead of pretending the port is protected.

## Current Scope

- Listens sockets from `ss -H -tulpen`
- Firewall signals from `nft list ruleset`
- Firewall signals from `iptables-save`
- UFW signals from `ufw status verbose`
- Docker published ports from `docker ps --format '{{json .}}'`
- TUI table with periodic refresh
- JSON output for scripting

## Installation

### From GitHub Releases

Download the latest Linux binary archive from the [releases page](https://github.com/Flaykz/snitch-fw/releases):

```bash
curl -L -o snitch-fw.tar.gz https://github.com/Flaykz/snitch-fw/releases/latest/download/snitch-fw-x86_64-unknown-linux-gnu.tar.gz
curl -L -o snitch-fw.tar.gz.sha256 https://github.com/Flaykz/snitch-fw/releases/latest/download/snitch-fw-x86_64-unknown-linux-gnu.tar.gz.sha256
sha256sum -c snitch-fw.tar.gz.sha256
tar -xzf snitch-fw.tar.gz
sudo install -m 0755 snitch-fw /usr/local/bin/snitch-fw
snitch-fw --help
```

The published binary targets `x86_64-unknown-linux-gnu`.

### From Source

Requirements:

- Rust stable with Cargo
- Linux for normal runtime usage

```bash
git clone https://github.com/Flaykz/snitch-fw.git
cd snitch-fw
cargo install --path .
snitch-fw --help
```

### Run Without Installing

```bash
cargo run -- --help
cargo run -- --json
cargo run -- --no-docker
```

## Usage

```bash
cargo run --
cargo run -- --json
cargo run -- --no-docker
cargo run -- --host-only
cargo run -- --full
cargo run -- --refresh 5
```

Some firewall and process details may require elevated privileges depending on your Linux distribution and local configuration.

## Build Linux Binary From Windows

Use Docker to build a Linux `x86_64` binary from Windows:

```powershell
.\scripts\build-linux.ps1
```

The binary is generated at:

```text
target\release\snitch-fw
```

Copy it to a VPS:

```powershell
scp -i "C:\Users\david\.ssh\id_ed25519_ovh" -P 22 ".\target\release\snitch-fw" flaykz@flaykz.ovh:~/snitch-fw
```

TUI shortcuts:

- `q` or `Esc`: quit
- `r`: refresh now
- `m`: cycle view mode (`global`, `all`, `local`, `container`)
- `up/down` or `k/j`: move details selection

The TUI starts in `global` mode by default. This hides loopback-only and container-only ports so the first screen focuses on ports that may matter for web exposure.

## Status Meanings

- `local-only`: the socket binds to loopback only.
- `firewalled`: a parsed local firewall rule drops or rejects the listener port.
- `exposed`: a parsed local firewall rule accepts the listener port, or the bind address is non-loopback and specific.
- `docker-published`: Docker publishes the host port.
- `ambiguous`: the listener binds to a wildcard address and firewall interpretation is incomplete.

## Limits

- External provider firewalls are not checked.
- nftables and iptables parsing is deliberately simple in this first version.
- Running without root may hide firewall details.
- IPv4 and IPv6 exposure should be reviewed separately in later versions.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions, validation commands and commit conventions.

This project uses [Semantic Release](https://semantic-release.gitbook.io/) with Conventional Commits. Use `feat:` for new features, `fix:` for bug fixes, and add a `BREAKING CHANGE:` footer for breaking changes.

## License

This project is licensed under the [MIT License](LICENSE).
