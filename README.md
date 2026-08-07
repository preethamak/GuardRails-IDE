# GuardRails IDE

GuardRails IDE is a security-first development environment built from a pinned
Code-OSS workbench and an independent native Rust security supervisor.

The editor provides the familiar workspace, editing, search, source control,
terminal, debugging, language-service, and extension experiences. GuardRails adds
enforceable boundaries for extensions, language tools, terminals, and AI agents:
they do not inherit ambient access to developer files, processes, network, or
credentials.

## Current status

This repository now contains Code-OSS 1.132.0 (`df53daabb18cd157bdb08c7f01c34df936cf12f4`)
and the initial Rust security harness. The policy evaluator and read-only filesystem
broker are tested prototypes. The Code-OSS shell is **not yet** connected to the Rust
supervisor, so extensions, terminals, and agents must not be described as sandboxed.

The public extension marketplace remains disabled while GuardRails develops a curated
extension catalog, signed capability manifests, and broker conformance tests.

## Repository layout

```text
src/                         Code-OSS workbench and platform sources
extensions/                  Built-in Code-OSS extensions
crates/guardrails-policy/    Deny-by-default capability evaluation
crates/guardrails-fs-broker/ Confined, audited workspace reads
docs/architecture/           GuardRails trust-boundary decisions
docs/planning/               Delivery roadmap and acceptance gates
```

## Development

Use the Node version recorded in `.nvmrc`, then install and compile the desktop
workbench:

```bash
npm ci
npm run compile
./scripts/code.sh
```

Validate the native security harness independently:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
```

## Linux installer builds

Run the **Package GuardRails IDE (Linux)** workflow from the Actions tab to build
the branded x64 Debian installer. The completed run publishes two downloadable
artifacts: `guardrails-ide-linux-amd64-deb` for installation with `apt`, and a
portable desktop bundle. These are unsigned development builds; release signing
for Windows and macOS requires the corresponding signing certificates.

## Security invariants

- No matching capability means denial; explicit denies override allows.
- Files, processes, network destinations, credentials, and tools are brokered.
- Approval is bound to one normalized request and expires.
- Secret values never enter model context or ordinary extension responses.
- Broker, policy, approval, and audit failures fail closed.

See [the architecture decision](docs/architecture/0001-code-oss-and-native-broker.md),
[the threat model](docs/architecture/threat-model.md), and
[the delivery roadmap](docs/planning/roadmap.md).
