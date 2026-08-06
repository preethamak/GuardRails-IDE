# Threat model

## Protected assets

- source, unreleased artifacts, and repository history;
- SSH, Git, package registry, cloud, signing, and deployment credentials;
- environment variables, browser sessions, keychains, and files outside a workspace;
- developer intent, approvals, organization policy, and audit evidence;
- build infrastructure and internal network services.

## Representative threats

| Threat | Required enforcement |
| --- | --- |
| Extension reads `.env` or `$HOME/.ssh` | workspace-scoped mounts plus canonical filesystem broker |
| Agent exfiltrates source | default-off network namespace and destination-bound proxy grant |
| Package script runs a second payload | process tree remains in the same sandbox and resource budget |
| Prompt injection requests a token | model never receives token; broker performs destination-bound use |
| Approved command changes after review | approval binds normalized request digest and expiration |
| Symlink or redirect escapes an allowlist | broker resolves each filesystem hop; proxy validates every redirect/IP |
| Extension update expands permissions | content digest changes principal identity and invalidates grants |
| Tool tampers with its audit trail | separate append-only writer identity and chained event hashes |

## Security boundary caveat

The policy library in this repository answers authorization questions; it is not an
OS sandbox. Production security also requires separate identities, mount/network
namespaces, resource limits, syscall restrictions, authenticated IPC, and enforcement
at the broker performing the operation.

## Initially out of scope

- protecting a host whose kernel or GuardRails trusted computing base is compromised;
- perfectly detecting data that an authorized principal transforms before sending;
- silently supporting legacy extensions that require ambient Node.js or host access;
- allowing arbitrary interactive shells to agents without explicit privileged mode.
