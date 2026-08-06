use guardrails_fs_broker::{AuditEvent, AuditSink, BrokerError, MemoryAuditSink, WorkspaceBroker};
use guardrails_policy::{Approval, Capability, Effect, Grant, Outcome, Request};
use std::{collections::BTreeSet, fs};
use tempfile::TempDir;

fn request(resource: &str) -> Request {
    Request {
        id: "read-1".into(),
        principal_id: "agent:test@1".into(),
        workspace_id: "workspace-1".into(),
        capability: Capability::Filesystem,
        action: "read".into(),
        resource: resource.into(),
        requested_at_ms: 100,
    }
}

fn rule(id: &str, pattern: &str, effect: Effect, approval: Approval) -> Grant {
    Grant {
        id: id.into(),
        principal_id: "agent:test@1".into(),
        workspace_id: "workspace-1".into(),
        capability: Capability::Filesystem,
        actions: BTreeSet::from(["read".into()]),
        resource_pattern: pattern.into(),
        effect,
        approval,
        expires_at_ms: None,
    }
}

fn workspace() -> TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("src")).unwrap();
    fs::write(root.path().join("src/main.rs"), b"fn main() {}\n").unwrap();
    fs::write(root.path().join(".env"), b"TOKEN=secret\n").unwrap();
    root
}

#[test]
fn reads_an_authorized_workspace_file_and_audits_decision() {
    let root = workspace();
    let audit = MemoryAuditSink::default();
    let broker = WorkspaceBroker::open(root.path(), audit.clone(), 1024).unwrap();
    let bytes = broker
        .read(
            &request("workspace/src/main.rs"),
            &[rule(
                "read-source",
                "workspace/src/**",
                Effect::Allow,
                Approval::Automatic,
            )],
        )
        .unwrap();

    assert_eq!(bytes, b"fn main() {}\n");
    let events = audit.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, Outcome::Allow);
    assert_eq!(events[0].matching_grant_id.as_deref(), Some("read-source"));
}

#[test]
fn an_explicit_secret_deny_overrides_a_broad_allow() {
    let root = workspace();
    let audit = MemoryAuditSink::default();
    let broker = WorkspaceBroker::open(root.path(), audit.clone(), 1024).unwrap();
    let result = broker.read(
        &request("workspace/.env"),
        &[
            rule("broad", "workspace/**", Effect::Allow, Approval::Automatic),
            rule(
                "secrets",
                "workspace/.env*",
                Effect::Deny,
                Approval::Automatic,
            ),
        ],
    );

    assert!(matches!(result, Err(BrokerError::Denied(_))));
    assert_eq!(audit.events()[0].outcome, Outcome::Deny);
    assert_eq!(
        audit.events()[0].matching_grant_id.as_deref(),
        Some("secrets")
    );
}

#[test]
fn prompt_grants_never_read_the_file() {
    let root = workspace();
    let broker = WorkspaceBroker::open(root.path(), MemoryAuditSink::default(), 1024).unwrap();
    let result = broker.read(
        &request("workspace/src/main.rs"),
        &[rule(
            "review",
            "workspace/src/**",
            Effect::Allow,
            Approval::Prompt,
        )],
    );
    assert!(matches!(result, Err(BrokerError::ApprovalRequired(_))));
}

#[test]
fn rejects_absolute_parent_and_non_normalized_paths_despite_broad_grant() {
    let root = workspace();
    let broker = WorkspaceBroker::open(root.path(), MemoryAuditSink::default(), 1024).unwrap();
    let broad = rule("broad", "**", Effect::Allow, Approval::Automatic);
    for resource in [
        "/etc/passwd",
        "workspace/../.env",
        "workspace/src/./main.rs",
        "workspace/src\\main.rs",
        "workspace/",
    ] {
        assert!(matches!(
            broker.read(&request(resource), std::slice::from_ref(&broad)),
            Err(BrokerError::InvalidResource)
        ));
    }
}

#[cfg(unix)]
#[test]
fn cannot_follow_a_symlink_outside_the_workspace() {
    use std::os::unix::fs::symlink;

    let root = workspace();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("secret"), b"outside").unwrap();
    symlink(outside.path().join("secret"), root.path().join("src/link")).unwrap();
    let broker = WorkspaceBroker::open(root.path(), MemoryAuditSink::default(), 1024).unwrap();
    let result = broker.read(
        &request("workspace/src/link"),
        &[rule(
            "source",
            "workspace/src/**",
            Effect::Allow,
            Approval::Automatic,
        )],
    );
    assert!(matches!(result, Err(BrokerError::Io(_))));
}

#[test]
fn enforces_read_size_limit() {
    let root = workspace();
    fs::write(root.path().join("src/large"), b"12345").unwrap();
    let broker = WorkspaceBroker::open(root.path(), MemoryAuditSink::default(), 4).unwrap();
    let result = broker.read(
        &request("workspace/src/large"),
        &[rule(
            "source",
            "workspace/src/**",
            Effect::Allow,
            Approval::Automatic,
        )],
    );
    assert!(matches!(result, Err(BrokerError::TooLarge { limit: 4 })));
}

struct FailingAudit;

impl AuditSink for FailingAudit {
    fn record(&self, _event: AuditEvent) -> Result<(), String> {
        Err("offline".into())
    }
}

#[test]
fn audit_failure_fails_closed_before_file_access() {
    let root = workspace();
    let broker = WorkspaceBroker::open(root.path(), FailingAudit, 1024).unwrap();
    let result = broker.read(
        &request("workspace/src/main.rs"),
        &[rule(
            "source",
            "workspace/src/**",
            Effect::Allow,
            Approval::Automatic,
        )],
    );
    assert!(matches!(result, Err(BrokerError::Audit(message)) if message == "offline"));
}
