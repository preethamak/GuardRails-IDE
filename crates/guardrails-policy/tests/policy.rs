use guardrails_policy::{
    Approval, Capability, Effect, Grant, Outcome, Reason, Request, evaluate, resource_matches,
};
use std::collections::BTreeSet;

fn request() -> Request {
    Request {
        id: "request-1".into(),
        principal_id: "agent:reviewer@sha256:123".into(),
        workspace_id: "workspace-1".into(),
        capability: Capability::Filesystem,
        action: "read".into(),
        resource: "workspace/src/main.rs".into(),
        requested_at_ms: 100,
    }
}

fn grant() -> Grant {
    Grant {
        id: "source-read".into(),
        principal_id: request().principal_id,
        workspace_id: request().workspace_id,
        capability: Capability::Filesystem,
        actions: BTreeSet::from(["read".into()]),
        resource_pattern: "workspace/src/**".into(),
        effect: Effect::Allow,
        approval: Approval::Automatic,
        expires_at_ms: None,
    }
}

#[test]
fn glob_language_is_segment_aware_and_literal() {
    let cases = [
        ("workspace/src/**", "workspace/src/main.rs", true),
        ("workspace/src/**", "workspace/src/a/main.rs", true),
        ("workspace/*.md", "workspace/README.md", true),
        ("workspace/*.md", "workspace/docs/README.md", false),
        ("https://api.test/**", "https://api.test/v1/data", true),
        ("https://api.test/**", "https://evil.test/v1/data", false),
        ("workspace/file?.rs", "workspace/file1.rs", false),
    ];
    for (pattern, value, expected) in cases {
        assert_eq!(
            resource_matches(pattern, value),
            expected,
            "{pattern} {value}"
        );
    }
}

#[test]
fn invalid_globs_fail_closed() {
    assert!(!resource_matches("", "workspace/file"));
    assert!(!resource_matches("workspace/**", "workspace/\0secret"));
    assert!(!resource_matches("workspace/**", "workspace/\nsecret"));
}

#[test]
fn unmatched_requests_are_denied() {
    let decision = evaluate(&request(), &[]);
    assert_eq!(decision.outcome, Outcome::Deny);
    assert_eq!(decision.reason, Reason::NoMatchingGrant);
    assert_eq!(decision.matching_grant_id, None);
}

#[test]
fn exact_scoped_grant_allows_request() {
    let decision = evaluate(&request(), &[grant()]);
    assert_eq!(decision.outcome, Outcome::Allow);
    assert_eq!(decision.reason, Reason::GrantAllowed);
    assert_eq!(decision.matching_grant_id.as_deref(), Some("source-read"));
}

#[test]
fn prompt_is_not_silently_treated_as_allow() {
    let mut gated = grant();
    gated.approval = Approval::Prompt;
    let decision = evaluate(&request(), &[gated]);
    assert_eq!(decision.outcome, Outcome::Prompt);
    assert_eq!(decision.reason, Reason::ApprovalRequired);
}

#[test]
fn explicit_deny_wins_in_any_order() {
    let mut deny = grant();
    deny.id = "deny-source".into();
    deny.effect = Effect::Deny;
    for rules in [vec![grant(), deny.clone()], vec![deny.clone(), grant()]] {
        let decision = evaluate(&request(), &rules);
        assert_eq!(decision.outcome, Outcome::Deny);
        assert_eq!(decision.reason, Reason::ExplicitDeny);
        assert_eq!(decision.matching_grant_id.as_deref(), Some("deny-source"));
    }
}

#[test]
fn authority_does_not_cross_any_scope_boundary() {
    let base = request();
    let variants = [
        Request {
            principal_id: "agent:other".into(),
            ..base.clone()
        },
        Request {
            workspace_id: "workspace-2".into(),
            ..base.clone()
        },
        Request {
            capability: Capability::Network,
            ..base.clone()
        },
        Request {
            action: "write".into(),
            ..base.clone()
        },
        Request {
            resource: "workspace/.env".into(),
            ..base
        },
    ];
    for variant in variants {
        assert_eq!(evaluate(&variant, &[grant()]).outcome, Outcome::Deny);
    }
}

#[test]
fn expiration_is_exclusive_and_fail_closed() {
    let mut expired = grant();
    expired.expires_at_ms = Some(100);
    assert_eq!(evaluate(&request(), &[expired]).outcome, Outcome::Deny);

    let mut live = grant();
    live.expires_at_ms = Some(101);
    assert_eq!(evaluate(&request(), &[live]).outcome, Outcome::Allow);
}

#[test]
fn malformed_requests_are_denied_before_matching() {
    let base = request();
    let variants = [
        Request {
            id: String::new(),
            ..base.clone()
        },
        Request {
            principal_id: "agent:\nother".into(),
            ..base.clone()
        },
        Request {
            workspace_id: " ".into(),
            ..base.clone()
        },
        Request {
            action: "\0read".into(),
            ..base.clone()
        },
        Request {
            resource: String::new(),
            ..base
        },
    ];
    for variant in variants {
        let decision = evaluate(&variant, &[grant()]);
        assert_eq!(decision.outcome, Outcome::Deny);
        assert_eq!(decision.reason, Reason::InvalidRequest);
    }
}

#[test]
fn decision_has_a_stable_json_contract() {
    let value = serde_json::to_value(evaluate(&request(), &[grant()])).unwrap();
    assert_eq!(value["outcome"], "allow");
    assert_eq!(value["reason"], "GRANT_ALLOWED");
    assert_eq!(value["request_id"], "request-1");
    assert_eq!(value["matching_grant_id"], "source-read");
}
