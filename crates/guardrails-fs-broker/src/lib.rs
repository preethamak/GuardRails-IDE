//! Workspace-confined filesystem reads mediated by `guardrails-policy`.

use cap_std::{ambient_authority, fs::Dir};
use guardrails_policy::{Decision, Grant, Outcome, Request, evaluate};
use serde::{Deserialize, Serialize};
use std::{
    io::{self, Read},
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
};
use thiserror::Error;

const RESOURCE_PREFIX: &str = "workspace/";

/// A secret-safe record emitted for every attempted broker operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditEvent {
    pub request_id: String,
    pub principal_id: String,
    pub workspace_id: String,
    pub action: String,
    pub resource: String,
    pub outcome: Outcome,
    pub reason: String,
    pub matching_grant_id: Option<String>,
}

/// Destination for authorization and operation events.
pub trait AuditSink: Send + Sync {
    /// # Errors
    ///
    /// Returns a secret-safe description when the event cannot be durably recorded.
    fn record(&self, event: AuditEvent) -> Result<(), String>;
}

/// In-memory sink intended for tests and local prototypes.
#[derive(Clone, Default)]
pub struct MemoryAuditSink(Arc<Mutex<Vec<AuditEvent>>>);

impl MemoryAuditSink {
    #[must_use]
    pub fn events(&self) -> Vec<AuditEvent> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl AuditSink for MemoryAuditSink {
    fn record(&self, event: AuditEvent) -> Result<(), String> {
        self.0
            .lock()
            .map_err(|_| "audit lock is poisoned".to_owned())?
            .push(event);
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum BrokerError {
    #[error("request was denied: {0:?}")]
    Denied(Decision),
    #[error("request requires approval: {0:?}")]
    ApprovalRequired(Decision),
    #[error("resource is not a normalized workspace path")]
    InvalidResource,
    #[error("file is larger than the configured read limit of {limit} bytes")]
    TooLarge { limit: u64 },
    #[error("audit sink failed: {0}")]
    Audit(String),
    #[error("filesystem operation failed: {0}")]
    Io(#[from] io::Error),
}

/// A filesystem authority rooted at one workspace directory.
pub struct WorkspaceBroker<A: AuditSink> {
    root: Dir,
    audit: A,
    max_read_bytes: u64,
}

impl<A: AuditSink> WorkspaceBroker<A> {
    /// Open a workspace root. This is a trusted bootstrap operation and therefore
    /// requires cap-std's explicit ambient-authority marker.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the root cannot be opened as a directory authority.
    pub fn open(root: impl AsRef<Path>, audit: A, max_read_bytes: u64) -> io::Result<Self> {
        Ok(Self {
            root: Dir::open_ambient_dir(root, ambient_authority())?,
            audit,
            max_read_bytes,
        })
    }

    /// Authorize and read a regular file without exposing the host root to callers.
    ///
    /// # Errors
    ///
    /// Denies invalid, unauthorized, approval-gated, oversized, non-regular, or
    /// inaccessible resources. Audit failures also fail the operation closed.
    pub fn read(&self, request: &Request, grants: &[Grant]) -> Result<Vec<u8>, BrokerError> {
        let relative = normalized_relative_path(&request.resource);
        let decision = evaluate(request, grants);

        self.audit
            .record(AuditEvent {
                request_id: request.id.clone(),
                principal_id: request.principal_id.clone(),
                workspace_id: request.workspace_id.clone(),
                action: request.action.clone(),
                resource: request.resource.clone(),
                outcome: decision.outcome,
                reason: format!("{:?}", decision.reason),
                matching_grant_id: decision.matching_grant_id.clone(),
            })
            .map_err(BrokerError::Audit)?;

        match decision.outcome {
            Outcome::Deny => return Err(BrokerError::Denied(decision)),
            Outcome::Prompt => return Err(BrokerError::ApprovalRequired(decision)),
            Outcome::Allow => {}
        }

        // Validate independently of policy. A broad policy grant must not turn an
        // absolute or parent-relative path into a host filesystem escape.
        let relative = relative?;
        let file = self.root.open(&relative)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(BrokerError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "resource is not a regular file",
            )));
        }
        if metadata.len() > self.max_read_bytes {
            return Err(BrokerError::TooLarge {
                limit: self.max_read_bytes,
            });
        }

        let mut bytes = Vec::with_capacity(metadata.len().try_into().unwrap_or(0));
        file.take(self.max_read_bytes + 1).read_to_end(&mut bytes)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > self.max_read_bytes {
            return Err(BrokerError::TooLarge {
                limit: self.max_read_bytes,
            });
        }
        Ok(bytes)
    }
}

fn normalized_relative_path(resource: &str) -> Result<PathBuf, BrokerError> {
    let relative = resource
        .strip_prefix(RESOURCE_PREFIX)
        .ok_or(BrokerError::InvalidResource)?;
    if relative.is_empty()
        || relative.contains('\\')
        || relative
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(BrokerError::InvalidResource);
    }

    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(BrokerError::InvalidResource);
    }
    Ok(path.to_owned())
}
