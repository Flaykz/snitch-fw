import { readFileSync, writeFileSync } from 'node:fs';

const version = process.argv[2];

if (!version) {
  console.error('Usage: node scripts/update-version.mjs <version>');
  process.exit(1);
}

const cargoTomlPath = 'Cargo.toml';
const cargoLockPath = 'Cargo.lock';

function replaceOrFail(content, pattern, replacement, path) {
  let matched = false;
  const updated = content.replace(pattern, (...args) => {
    matched = true;
    return replacement(...args);
  });

  if (!matched) {
    console.error(`Could not update version in ${path}`);
    process.exit(1);
  }

  return updated;
}

const cargoToml = readFileSync(cargoTomlPath, 'utf8');
const updatedCargoToml = replaceOrFail(
  cargoToml,
  /(^\[package\][\s\S]*?^version\s*=\s*")([^"]+)(")/m,
  (_match, before, _current, after) => `${before}${version}${after}`,
  cargoTomlPath,
);

writeFileSync(cargoTomlPath, updatedCargoToml);

const cargoLock = readFileSync(cargoLockPath, 'utf8');
const updatedCargoLock = replaceOrFail(
  cargoLock,
  /(\[\[package\]\]\r?\nname = "snitch-fw"\r?\nversion = ")([^"]+)(")/,
  (_match, before, _current, after) => `${before}${version}${after}`,
  cargoLockPath,
);

writeFileSync(cargoLockPath, updatedCargoLock);
