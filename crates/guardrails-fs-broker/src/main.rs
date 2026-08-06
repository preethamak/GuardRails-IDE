use guardrails_fs_broker::{MemoryAuditSink, WorkspaceBroker};
use guardrails_policy::{Approval, Capability, Effect, Grant, Request};
use std::{collections::BTreeSet, env, process::ExitCode};

fn usage() -> ExitCode {
    eprintln!(
        "usage: guardrails-fs-broker <workspace-root> <principal> <relative-path> <allow-pattern>"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let [root, principal, relative, allow_pattern] = args.as_slice() else {
        return usage();
    };
    let resource = format!("workspace/{relative}");
    let request = Request {
        id: "cli-read".into(),
        principal_id: principal.clone(),
        workspace_id: "cli-workspace".into(),
        capability: Capability::Filesystem,
        action: "read".into(),
        resource,
        requested_at_ms: 0,
    };
    let common = Grant {
        id: "cli-allow".into(),
        principal_id: principal.clone(),
        workspace_id: "cli-workspace".into(),
        capability: Capability::Filesystem,
        actions: BTreeSet::from(["read".into()]),
        resource_pattern: allow_pattern.clone(),
        effect: Effect::Allow,
        approval: Approval::Automatic,
        expires_at_ms: None,
    };
    let root_secret_deny = Grant {
        id: "builtin-root-secret-deny".into(),
        resource_pattern: "workspace/.env*".into(),
        effect: Effect::Deny,
        ..common.clone()
    };
    let nested_secret_deny = Grant {
        id: "builtin-nested-secret-deny".into(),
        resource_pattern: "workspace/**/.env*".into(),
        effect: Effect::Deny,
        ..common.clone()
    };
    let audit = MemoryAuditSink::default();
    let broker = match WorkspaceBroker::open(root, audit.clone(), 1024 * 1024) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("failed to open workspace: {error}");
            return ExitCode::FAILURE;
        }
    };

    match broker.read(&request, &[common, root_secret_deny, nested_secret_deny]) {
        Ok(bytes) => {
            print!("{}", String::from_utf8_lossy(&bytes));
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            if let Some(event) = audit.events().last() {
                eprintln!("audit: {} {}", event.outcome_string(), event.reason);
            }
            ExitCode::FAILURE
        }
    }
}

trait OutcomeDisplay {
    fn outcome_string(&self) -> &'static str;
}

impl OutcomeDisplay for guardrails_fs_broker::AuditEvent {
    fn outcome_string(&self) -> &'static str {
        match self.outcome {
            guardrails_policy::Outcome::Allow => "allow",
            guardrails_policy::Outcome::Deny => "deny",
            guardrails_policy::Outcome::Prompt => "prompt",
        }
    }
}
