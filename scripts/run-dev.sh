#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workspace="${1:-${repo_root}}"

cd "${repo_root}"
exec cargo run --locked -p guardrails-ide -- --workspace "${workspace}"
