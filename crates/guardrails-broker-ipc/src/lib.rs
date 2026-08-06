//! Length-delimited, authenticated IPC dispatch for local `GuardRails` brokers.

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use guardrails_fs_broker::{AuditSink, BrokerError, WorkspaceBroker};
use guardrails_policy::{Capability, Grant, Request};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use subtle::ConstantTimeEq;
use thiserror::Error;

pub const PROTOCOL_VERSION: u16 = 1;
pub const DEFAULT_MAX_FRAME_BYTES: usize = 64 * 1024;

/// The only request currently exposed over IPC. Principal, workspace, capability, and
/// action are intentionally absent; the trusted supervisor binds those values.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReadFileRequest {
    pub version: u16,
    pub request_id: String,
    pub session_token: String,
    pub resource: String,
    pub requested_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    UnsupportedVersion,
    AuthenticationFailed,
    InvalidRequest,
    Denied,
    ApprovalRequired,
    TooLarge,
    BrokerFailure,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReadFileResponse {
    Ok {
        request_id: String,
        content_base64: String,
    },
    Error {
        request_id: String,
        code: ErrorCode,
    },
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("frame length {actual} exceeds limit {limit}")]
    FrameTooLarge { actual: usize, limit: usize },
    #[error("invalid JSON frame: {0}")]
    InvalidJson(#[from] serde_json::Error),
}

/// A session established by the trusted supervisor after authenticating a sandbox.
pub struct BrokerSession<A: AuditSink> {
    principal_id: String,
    workspace_id: String,
    session_token: String,
    broker: WorkspaceBroker<A>,
    grants: Vec<Grant>,
    max_frame_bytes: usize,
}

impl<A: AuditSink> BrokerSession<A> {
    #[must_use]
    pub fn new(
        principal_id: String,
        workspace_id: String,
        session_token: String,
        broker: WorkspaceBroker<A>,
        grants: Vec<Grant>,
    ) -> Self {
        Self {
            principal_id,
            workspace_id,
            session_token,
            broker,
            grants,
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
        }
    }

    #[must_use]
    pub fn with_max_frame_bytes(mut self, max_frame_bytes: usize) -> Self {
        self.max_frame_bytes = max_frame_bytes;
        self
    }

    /// Read one request frame and write one response frame.
    ///
    /// # Errors
    ///
    /// Returns an error for transport failures, oversized frames, or malformed JSON.
    /// Authentication and broker denials are encoded as bounded response frames.
    pub fn serve_one<S: Read + Write>(&self, stream: &mut S) -> Result<(), ProtocolError> {
        let payload = read_frame(stream, self.max_frame_bytes)?;
        let request: ReadFileRequest = serde_json::from_slice(&payload)?;
        let response = self.dispatch(request);
        let encoded = serde_json::to_vec(&response)?;
        write_frame(stream, &encoded, self.max_frame_bytes)
    }

    fn dispatch(&self, wire: ReadFileRequest) -> ReadFileResponse {
        if wire.version != PROTOCOL_VERSION {
            return error(wire.request_id, ErrorCode::UnsupportedVersion);
        }
        if !valid_session_token(&self.session_token, &wire.session_token) {
            return error(wire.request_id, ErrorCode::AuthenticationFailed);
        }

        let request = Request {
            id: wire.request_id.clone(),
            principal_id: self.principal_id.clone(),
            workspace_id: self.workspace_id.clone(),
            capability: Capability::Filesystem,
            action: "read".into(),
            resource: wire.resource,
            requested_at_ms: wire.requested_at_ms,
        };
        match self.broker.read(&request, &self.grants) {
            Ok(content) => ReadFileResponse::Ok {
                request_id: wire.request_id,
                content_base64: BASE64.encode(content),
            },
            Err(failure) => error(wire.request_id, broker_error_code(&failure)),
        }
    }
}

fn valid_session_token(expected: &str, supplied: &str) -> bool {
    // Tokens are fixed-size, high-entropy values issued by the supervisor. Rejecting
    // unexpected lengths also prevents accidental use of human passwords.
    expected.len() >= 32
        && expected.len() == supplied.len()
        && bool::from(expected.as_bytes().ct_eq(supplied.as_bytes()))
}

fn broker_error_code(error: &BrokerError) -> ErrorCode {
    match error {
        BrokerError::Denied(_) => ErrorCode::Denied,
        BrokerError::ApprovalRequired(_) => ErrorCode::ApprovalRequired,
        BrokerError::InvalidResource => ErrorCode::InvalidRequest,
        BrokerError::TooLarge { .. } => ErrorCode::TooLarge,
        BrokerError::Audit(_) | BrokerError::Io(_) => ErrorCode::BrokerFailure,
    }
}

fn error(request_id: String, code: ErrorCode) -> ReadFileResponse {
    ReadFileResponse::Error { request_id, code }
}

/// Read a big-endian 32-bit length-delimited frame.
///
/// # Errors
///
/// Rejects incomplete I/O and frames larger than the configured bound before
/// allocating their payload.
pub fn read_frame<R: Read>(reader: &mut R, limit: usize) -> Result<Vec<u8>, ProtocolError> {
    let mut header = [0_u8; 4];
    reader.read_exact(&mut header)?;
    let length = usize::try_from(u32::from_be_bytes(header)).unwrap_or(usize::MAX);
    if length > limit {
        return Err(ProtocolError::FrameTooLarge {
            actual: length,
            limit,
        });
    }
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload)?;
    Ok(payload)
}

/// Write a big-endian 32-bit length-delimited frame.
///
/// # Errors
///
/// Rejects payloads larger than the configured or 32-bit protocol bounds and returns
/// underlying I/O errors.
pub fn write_frame<W: Write>(
    writer: &mut W,
    payload: &[u8],
    limit: usize,
) -> Result<(), ProtocolError> {
    if payload.len() > limit || payload.len() > u32::MAX as usize {
        return Err(ProtocolError::FrameTooLarge {
            actual: payload.len(),
            limit: limit.min(u32::MAX as usize),
        });
    }
    let frame_length = u32::try_from(payload.len()).map_err(|_| ProtocolError::FrameTooLarge {
        actual: payload.len(),
        limit: limit.min(u32::MAX as usize),
    })?;
    writer.write_all(&frame_length.to_be_bytes())?;
    writer.write_all(payload)?;
    writer.flush()?;
    Ok(())
}
