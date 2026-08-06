//! Deterministic, deny-by-default authorization for `GuardRails` broker requests.
//!
//! Resource canonicalization and the operation itself remain broker responsibilities.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Broker boundary being requested.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Filesystem,
    Process,
    Network,
    Secret,
    Clipboard,
    Editor,
    Tool,
}

/// Whether a matching rule grants or rejects authority.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Allow,
    Deny,
}

/// Whether a grant is immediate or needs an exact-action human approval.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Approval {
    Automatic,
    Prompt,
}

/// A normalized request created by a resource broker.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Request {
    pub id: String,
    pub principal_id: String,
    pub workspace_id: String,
    pub capability: Capability,
    pub action: String,
    pub resource: String,
    /// Unix time in milliseconds, supplied by the trusted broker.
    pub requested_at_ms: u64,
}

/// A versioned capability rule. Rules are immutable within an evaluation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Grant {
    pub id: String,
    pub principal_id: String,
    pub workspace_id: String,
    pub capability: Capability,
    pub actions: BTreeSet<String>,
    pub resource_pattern: String,
    pub effect: Effect,
    pub approval: Approval,
    pub expires_at_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Allow,
    Deny,
    Prompt,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Reason {
    InvalidRequest,
    ExplicitDeny,
    NoMatchingGrant,
    ApprovalRequired,
    GrantAllowed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Decision {
    pub outcome: Outcome,
    pub reason: Reason,
    pub request_id: String,
    pub matching_grant_id: Option<String>,
}

impl Decision {
    fn new(request: &Request, outcome: Outcome, reason: Reason, grant: Option<&Grant>) -> Self {
        Self {
            outcome,
            reason,
            request_id: request.id.clone(),
            matching_grant_id: grant.map(|item| item.id.clone()),
        }
    }
}

fn valid_token(value: &str) -> bool {
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}

fn valid_request(request: &Request) -> bool {
    valid_token(&request.id)
        && valid_token(&request.principal_id)
        && valid_token(&request.workspace_id)
        && valid_token(&request.action)
        && valid_token(&request.resource)
}

/// Match the intentionally small policy glob language: `*` stays inside one `/`
/// segment and `**` crosses segments. All other characters are literal.
#[must_use]
pub fn resource_matches(pattern: &str, resource: &str) -> bool {
    if !valid_token(pattern) || !valid_token(resource) {
        return false;
    }
    glob_match(pattern.as_bytes(), resource.as_bytes())
}

fn glob_match(pattern: &[u8], value: &[u8]) -> bool {
    let (mut p, mut v) = (0, 0);
    let mut single_star = None;
    let mut double_star = None;

    while v < value.len() {
        if p < pattern.len() && pattern[p] == b'*' {
            if p + 1 < pattern.len() && pattern[p + 1] == b'*' {
                double_star = Some((p + 2, v));
                p += 2;
            } else {
                single_star = Some((p + 1, v));
                p += 1;
            }
        } else if p < pattern.len() && pattern[p] == value[v] {
            p += 1;
            v += 1;
        } else if let Some((next, start)) = single_star {
            if start < value.len() && value[start] != b'/' {
                let advanced = start + 1;
                single_star = Some((next, advanced));
                p = next;
                v = advanced;
            } else if let Some((next, start)) = double_star {
                let advanced = start + 1;
                double_star = Some((next, advanced));
                single_star = None;
                p = next;
                v = advanced;
            } else {
                return false;
            }
        } else if let Some((next, start)) = double_star {
            let advanced = start + 1;
            double_star = Some((next, advanced));
            p = next;
            v = advanced;
        } else {
            return false;
        }
    }

    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

fn grant_matches(grant: &Grant, request: &Request) -> bool {
    grant.principal_id == request.principal_id
        && grant.workspace_id == request.workspace_id
        && grant.capability == request.capability
        && grant.actions.contains(&request.action)
        && resource_matches(&grant.resource_pattern, &request.resource)
        && grant
            .expires_at_ms
            .is_none_or(|expiration| expiration > request.requested_at_ms)
}

/// Evaluate grants with explicit-deny precedence and default denial.
#[must_use]
pub fn evaluate(request: &Request, grants: &[Grant]) -> Decision {
    if !valid_request(request) {
        return Decision::new(request, Outcome::Deny, Reason::InvalidRequest, None);
    }

    let matching: Vec<&Grant> = grants
        .iter()
        .filter(|grant| grant_matches(grant, request))
        .collect();

    if let Some(denied) = matching.iter().find(|grant| grant.effect == Effect::Deny) {
        return Decision::new(request, Outcome::Deny, Reason::ExplicitDeny, Some(denied));
    }

    let Some(allowed) = matching.iter().find(|grant| grant.effect == Effect::Allow) else {
        return Decision::new(request, Outcome::Deny, Reason::NoMatchingGrant, None);
    };

    match allowed.approval {
        Approval::Automatic => {
            Decision::new(request, Outcome::Allow, Reason::GrantAllowed, Some(allowed))
        }
        Approval::Prompt => Decision::new(
            request,
            Outcome::Prompt,
            Reason::ApprovalRequired,
            Some(allowed),
        ),
    }
}
