Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")

docker run --rm `
  -v "${projectRoot}:/work" `
  -w /work `
  rust:1.94-slim `
  sh -lc 'export PATH=/usr/local/cargo/bin:/usr/local/rustup/toolchains/1.94.0-x86_64-unknown-linux-gnu/bin:$PATH; cargo build --release'

Write-Host "Built Linux binary: $projectRoot\target\release\snitch-fw"
