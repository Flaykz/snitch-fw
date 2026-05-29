# Contributing

Thanks for taking the time to improve `snitch-fw`.

## Development Setup

Requirements:

- Rust stable with Cargo
- Linux for runtime testing of socket, firewall, UFW and Docker collection
- Docker, only if you want to test Docker published port detection or build the Linux binary from Windows

Install the toolchain from <https://rustup.rs>, then check the project:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

Run locally:

```bash
cargo run -- --help
cargo run -- --json
cargo run -- --no-docker
```

## Commit Convention

This project uses Semantic Release. Commit messages must follow Conventional Commits so releases can be generated automatically.

Examples:

```text
feat: add nftables verdict parsing
fix: avoid marking loopback sockets as exposed
docs: document Docker detection limits
chore: update CI toolchain
```

Release impact:

- `fix:` creates a patch release.
- `feat:` creates a minor release.
- `BREAKING CHANGE:` in the commit footer creates a major release.
- `docs:`, `test:`, `chore:`, `refactor:` usually do not create a release by themselves.

## Pull Requests

- Keep changes focused and small enough to review.
- Add or update tests when behavior changes.
- Update `README.md` when user-facing behavior changes.
- Run `cargo fmt`, `cargo clippy` and `cargo test` before requesting review.

## Runtime Notes

Some collectors depend on Linux host commands such as `ss`, `nft`, `iptables-save`, `ufw` and `docker`. If a change affects these integrations, include the command output shape or fixtures used to validate it.
