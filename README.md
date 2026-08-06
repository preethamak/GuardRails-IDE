# GuardRails IDE

GuardRails IDE is a security-first development environment for running extensions,
language tools, terminals, and AI agents without ambient access to developer data.

The project is starting with the security kernel rather than a cosmetic editor clone.
The first executable component is a deny-by-default capability policy engine. Every
later filesystem, process, network, secret, and tool broker will depend on this small,
testable contract.

## Repository layout

```text
crates/guardrails-policy/   Capability model and deterministic evaluator
docs/architecture/         Trust boundaries and repository decisions
docs/planning/             Phases, milestones, and acceptance gates
```

## Quick start

```bash
cargo test --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
```

## Product invariants

- No extension or agent inherits the IDE process environment or host identity.
- No matching capability means denial.
- Explicit deny rules override allows.
- Files, processes, network destinations, secrets, and tools are brokered resources.
- Approval is bound to an exact normalized request, not a vague session prompt.
- Secret values never enter model context or ordinary extension responses.
- Every security decision emits secret-safe audit metadata.

See [the architecture decision](docs/architecture/0001-code-oss-and-native-broker.md)
and [delivery plan](docs/planning/roadmap.md) for the implementation strategy.
