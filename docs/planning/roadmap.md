# Delivery plan

## Phase 0 — Security contract (current)

Deliver the capability schema, deterministic evaluator, adversarial tests, threat
model, and editor-shell decision. Exit when malformed and unmatched requests fail
closed, explicit denies win, approvals are distinguishable from allows, and CI runs
formatting, linting, and tests.

## Phase 1 — Linux secure workspace MVP

Build a Rust supervisor with authenticated local IPC. Add symlink-safe filesystem,
structured process, network egress, credential, and append-only audit brokers. Embed
a pinned Code-OSS/Monaco shell with extension installation disabled. Run one sample
agent and one sample formatter under separate identities with empty environments.

**Exit gate:** an in-sandbox adversarial suite cannot read host secrets, escape the
workspace, reach undeclared destinations, inherit credentials, or spawn outside its
resource limits.

## Phase 2 — Agent workflow and permission center

Add review-first patches, exact-action approval leases, revocation, agent/tool
delegation, redacted output, and human-readable audit timelines. No model receives raw
secret values; destination-bound operations use opaque credential handles.

**Exit gate:** end-to-end tests prove approval binding, revocation, delegation
attenuation, secret redaction, and recovery after broker failure.

## Phase 3 — Extension compatibility

Define signed capability manifests and a VS Code API adapter. Enable a curated set of
formatters, language servers, linters, and debuggers only after each category passes
functional and security conformance. Display permission diffs on every update.

**Exit gate:** no supported extension can bypass its declared filesystem, process,
network, secret, clipboard, or tool capabilities.

## Phase 4 — Teams and remote workspaces

Add organization policy bundles, locked denies, SSO, short-lived workload identity,
remote ephemeral sandboxes, audit export, policy simulation, and incident revocation.

## Phase 5 — Cross-platform public beta

Reach equivalent controls using Linux namespaces/Landlock/seccomp, macOS sandbox and
hardened runtime, and Windows AppContainer/restricted tokens/job objects/WFP. Require
reproducible signed builds, SBOM/provenance, independent penetration testing, and no
open critical or high findings.

## First implementation sequence

1. ~~Capability evaluator and test corpus.~~ Completed in Phase 0.
2. ~~Read-only filesystem broker vertical slice.~~ Completed with confined traversal,
   audit integration, size limits, a CLI, and adversarial tests.
3. Versioned IPC protocol and request authentication.
4. Filesystem write/apply broker with review-digest binding and rollback.
5. Process sandbox, egress proxy, and resource limits.
6. Opaque credential flow and production audit chain.
7. Code-OSS shell spike and permission center.
8. Agent patch/review/apply workflow.

Broad editor customization and marketplace compatibility remain behind the native
isolation gate; visual progress must not outrun enforceable boundaries.
