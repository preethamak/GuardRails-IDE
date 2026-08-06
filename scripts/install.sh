#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v cargo >/dev/null 2>&1; then
  echo "Rust is required. Install it from https://rustup.rs and run this script again." >&2
  exit 1
fi

echo "Installing GuardRails IDE from ${repo_root}..."
cargo install --locked --path "${repo_root}/crates/guardrails-ide"
echo
echo "Installed. Open a project with:"
echo "  guardrails-ide --workspace /path/to/project"
echo "Then visit http://127.0.0.1:43110"
