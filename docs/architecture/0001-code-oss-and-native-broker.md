# ADR 0001: Code-OSS shell with an independent native security broker

**Status:** Accepted for prototyping  
**Date:** 2026-08-06

## Context

GuardRails needs mature editing, language-server, debugging, accessibility, and
source-control experiences. Rebuilding these features before validating isolation
would consume years and still leave the dangerous part—ambient extension authority—
unsolved. A browser-only shell also cannot enforce host process or network policy.

## Decision

We will evaluate a pinned Code-OSS fork as the desktop/editor shell while keeping the
trusted security kernel in a separate Rust supervisor. Code-OSS is not the security
boundary. Its extension host, renderers, terminals, language servers, workspace code,
and AI tools are untrusted principals.

All privileged operations cross versioned broker APIs:

```text
Code-OSS renderer (untrusted web content)
       | narrow authenticated IPC
Rust supervisor / capability broker
       |-- policy evaluator and approval leases
       |-- filesystem broker (canonical path handles)
       |-- process broker (structured executable + arguments)
       |-- network broker (destination-bound egress proxy)
       |-- credential broker (opaque secret handles)
       `-- append-only audit writer
```

The fork will initially disable the upstream marketplace and arbitrary extension
installation. Extensions return only after a manifest adapter and sandbox conformance
suite exist. We will track upstream through a minimal patch queue instead of mixing
security services into editor source.

## Trust boundaries

Trusted computing base:

1. native supervisor and broker implementations;
2. policy store and evaluator;
3. approval UI path, including request-digest display;
4. credential broker and audit writer;
5. OS isolation primitives.

Everything else is untrusted, including models, MCP servers, package scripts,
debuggers, repository configuration, extension updates, and tool output.

## Non-negotiable controls

- Each principal has a distinct identity, sandbox, empty environment, storage, and
  revocable capability set.
- The broker canonicalizes resources before evaluating policy. A policy glob never
  substitutes for symlink-safe filesystem traversal or proxy-side network controls.
- Delegation can only reduce authority and records the full principal chain.
- Approval is bound to principal, normalized request, policy version, digest, and
  expiration.
- Broker, policy, audit, or approval failures fail closed.

## Consequences

Code-OSS compatibility will be deliberately incomplete. Some extensions must be
adapted, remotely contained, or rejected. In exchange, editor updates can remain
largely separate from the security kernel, and every supported operating system can
run the same broker conformance suite.

Before committing to a long-lived fork, Phase 1 must prove that the native supervisor
can isolate a sample extension and agent on Linux. If Code-OSS integration forces
privileged extension compatibility, we will retain Monaco and open protocols while
replacing the shell.
