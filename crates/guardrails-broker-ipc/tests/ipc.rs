#![cfg(unix)]

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use guardrails_broker_ipc::{
    BrokerSession, DEFAULT_MAX_FRAME_BYTES, ErrorCode, ProtocolError, ReadFileRequest,
    ReadFileResponse, read_frame, write_frame,
};
use guardrails_fs_broker::{MemoryAuditSink, WorkspaceBroker};
use guardrails_policy::{Approval, Capability, Effect, Grant, Outcome};
use std::{collections::BTreeSet, fs, os::unix::net::UnixStream, thread};

const TOKEN: &str = "0123456789abcdef0123456789abcdef";

fn grant(principal: &str, effect: Effect) -> Grant {
    Grant {
        id: format!("{effect:?}-source"),
        principal_id: principal.into(),
        workspace_id: "workspace-1".into(),
        capability: Capability::Filesystem,
        actions: BTreeSet::from(["read".into()]),
        resource_pattern: "workspace/src/**".into(),
        effect,
        approval: Approval::Automatic,
        expires_at_ms: None,
    }
}

fn setup(
    grants: Vec<Grant>,
) -> (
    BrokerSession<MemoryAuditSink>,
    MemoryAuditSink,
    tempfile::TempDir,
) {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("src")).unwrap();
    fs::write(root.path().join("src/main.rs"), b"fn main() {}\n").unwrap();
    let audit = MemoryAuditSink::default();
    let broker = WorkspaceBroker::open(root.path(), audit.clone(), 1024).unwrap();
    (
        BrokerSession::new(
            "agent:bound@1".into(),
            "workspace-1".into(),
            TOKEN.into(),
            broker,
            grants,
        ),
        audit,
        root,
    )
}

fn request(token: &str) -> ReadFileRequest {
    ReadFileRequest {
        version: 1,
        request_id: "ipc-1".into(),
        session_token: token.into(),
        resource: "workspace/src/main.rs".into(),
        requested_at_ms: 100,
    }
}

fn round_trip(
    session: BrokerSession<MemoryAuditSink>,
    request: &ReadFileRequest,
) -> ReadFileResponse {
    let (mut client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || session.serve_one(&mut server));
    write_frame(
        &mut client,
        &serde_json::to_vec(request).unwrap(),
        DEFAULT_MAX_FRAME_BYTES,
    )
    .unwrap();
    let response = read_frame(&mut client, DEFAULT_MAX_FRAME_BYTES).unwrap();
    worker.join().unwrap().unwrap();
    serde_json::from_slice(&response).unwrap()
}

#[test]
fn authenticated_socket_request_reads_as_supervisor_bound_principal() {
    let (session, audit, _root) = setup(vec![grant("agent:bound@1", Effect::Allow)]);
    let response = round_trip(session, &request(TOKEN));
    let ReadFileResponse::Ok {
        request_id,
        content_base64,
    } = response
    else {
        panic!("expected successful response");
    };
    assert_eq!(request_id, "ipc-1");
    assert_eq!(BASE64.decode(content_base64).unwrap(), b"fn main() {}\n");
    assert_eq!(audit.events()[0].principal_id, "agent:bound@1");
    assert_eq!(audit.events()[0].outcome, Outcome::Allow);
}

#[test]
fn invalid_token_is_rejected_before_policy_and_audit() {
    let (session, audit, _root) = setup(vec![grant("agent:bound@1", Effect::Allow)]);
    assert_eq!(
        round_trip(session, &request("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")),
        ReadFileResponse::Error {
            request_id: "ipc-1".into(),
            code: ErrorCode::AuthenticationFailed,
        }
    );
    assert!(audit.events().is_empty());
}

#[test]
fn unsupported_version_is_rejected_before_authentication() {
    let (session, audit, _root) = setup(vec![grant("agent:bound@1", Effect::Allow)]);
    let mut future = request(TOKEN);
    future.version = 2;
    assert_eq!(
        round_trip(session, &future),
        ReadFileResponse::Error {
            request_id: "ipc-1".into(),
            code: ErrorCode::UnsupportedVersion,
        }
    );
    assert!(audit.events().is_empty());
}

#[test]
fn wire_request_cannot_claim_a_different_principal() {
    let (session, _audit, _root) = setup(vec![grant("agent:bound@1", Effect::Allow)]);
    let (mut client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || session.serve_one(&mut server));
    let mut value = serde_json::to_value(request(TOKEN)).unwrap();
    value["principal_id"] = "agent:admin@1".into();
    write_frame(
        &mut client,
        &serde_json::to_vec(&value).unwrap(),
        DEFAULT_MAX_FRAME_BYTES,
    )
    .unwrap();
    drop(client);
    assert!(matches!(
        worker.join().unwrap(),
        Err(ProtocolError::InvalidJson(_))
    ));
}

#[test]
fn broker_denial_is_a_stable_non_secret_response() {
    let (session, audit, _root) = setup(vec![grant("agent:bound@1", Effect::Deny)]);
    assert_eq!(
        round_trip(session, &request(TOKEN)),
        ReadFileResponse::Error {
            request_id: "ipc-1".into(),
            code: ErrorCode::Denied,
        }
    );
    assert_eq!(audit.events()[0].outcome, Outcome::Deny);
}

#[test]
fn oversized_frame_is_rejected_before_payload_allocation() {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&1024_u32.to_be_bytes());
    assert!(matches!(
        read_frame(&mut encoded.as_slice(), 32),
        Err(ProtocolError::FrameTooLarge {
            actual: 1024,
            limit: 32
        })
    ));
}

#[test]
fn truncated_frames_fail_without_dispatch() {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&10_u32.to_be_bytes());
    encoded.extend_from_slice(b"short");
    assert!(matches!(
        read_frame(&mut encoded.as_slice(), 32),
        Err(ProtocolError::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof
    ));
}
