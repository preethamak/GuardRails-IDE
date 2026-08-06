//! Authenticated, versioned local IPC for the GuardRails trusted supervisor.
//!
//! This crate deliberately exposes only the bootstrap handshake. Resource operations
//! are added only after their corresponding broker can enforce them.

use serde::{Deserialize, Serialize};
use std::{
	io::{self, BufRead, BufReader, Write},
	net::{SocketAddr, TcpListener, TcpStream},
};
use thiserror::Error;

/// The only protocol version accepted by this implementation.
pub const PROTOCOL_VERSION: u16 = 1;
/// The maximum accepted line-delimited JSON message size.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// A bootstrap request from a process launched by the trusted supervisor.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HandshakeRequest {
	pub protocol_version: u16,
	pub launch_token: String,
	pub principal_id: String,
}

/// An authenticated identity bound to one accepted connection.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HandshakeResponse {
	pub protocol_version: u16,
	pub principal_id: String,
}

/// Secret-safe supervisor state returned only after a successful handshake.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SupervisorStatus {
	pub protocol_version: u16,
	pub policy_engine: ComponentStatus,
	pub filesystem_broker: ComponentStatus,
}

/// A component state that does not reveal host details or credential material.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentStatus {
	Ready,
}

/// Fail-closed handshake response suitable for an untrusted client.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RejectionResponse {
	pub code: RejectionCode,
}

/// Secret-safe failure categories; server implementation details never cross IPC.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionCode {
	InvalidRequest,
	UnsupportedProtocol,
	AuthenticationFailed,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ClientMessage {
	Handshake(HandshakeRequest),
	Status,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ServerMessage {
	Accepted(HandshakeResponse),
	Status(SupervisorStatus),
	Rejected(RejectionResponse),
}

/// Errors surfaced to the trusted launcher, never sent as raw errors to a client.
#[derive(Debug, Error)]
pub enum SupervisorError {
	#[error("launch token must not be empty")]
	EmptyLaunchToken,
	#[error("I/O failure: {0}")]
	Io(#[from] io::Error),
	#[error("serialization failure: {0}")]
	Json(#[from] serde_json::Error),
}

/// A one-connection authenticated local supervisor listener.
pub struct Supervisor {
	listener: TcpListener,
	launch_token: String,
}

impl Supervisor {
	/// Bind only to a caller-selected local address and retain its launch token.
	///
	/// # Errors
	/// Returns an error when the token is empty or the listener cannot bind.
	pub fn bind(address: SocketAddr, launch_token: String) -> Result<Self, SupervisorError> {
		if launch_token.is_empty() {
			return Err(SupervisorError::EmptyLaunchToken);
		}
		Ok(Self { listener: TcpListener::bind(address)?, launch_token })
	}

	/// The resolved local address that a supervisor-launched client may connect to.
	///
	/// # Errors
	/// Returns an error when the listener address cannot be read.
	pub fn local_addr(&self) -> Result<SocketAddr, SupervisorError> {
		Ok(self.listener.local_addr()?)
	}

	/// Accept, authenticate, and serve one status request from a client connection.
	///
	/// # Errors
	/// Returns I/O and serialization failures to the trusted launcher. Invalid client
	/// messages receive a redacted rejection and do not authenticate a principal.
	pub fn serve_once(&self) -> Result<Option<String>, SupervisorError> {
		let (mut stream, _) = self.listener.accept()?;
		let mut reader = BufReader::new(stream.try_clone()?);
		let message = read_message(&mut reader)?;
		let response = match message {
			Ok(ClientMessage::Handshake(request)) if request.protocol_version != PROTOCOL_VERSION => {
				ServerMessage::Rejected(RejectionResponse { code: RejectionCode::UnsupportedProtocol })
			}
			Ok(ClientMessage::Handshake(request)) if request.launch_token != self.launch_token || !valid_principal(&request.principal_id) => {
				ServerMessage::Rejected(RejectionResponse { code: RejectionCode::AuthenticationFailed })
			}
			Ok(ClientMessage::Handshake(request)) => ServerMessage::Accepted(HandshakeResponse {
				protocol_version: PROTOCOL_VERSION,
				principal_id: request.principal_id,
			}),
			Ok(ClientMessage::Status) => ServerMessage::Rejected(RejectionResponse { code: RejectionCode::InvalidRequest }),
			Err(()) => ServerMessage::Rejected(RejectionResponse { code: RejectionCode::InvalidRequest }),
		};
		write_message(&mut stream, &response)?;
		let ServerMessage::Accepted(response) = response else {
			return Ok(None);
		};
		let principal_id = response.principal_id;
		let response = match read_message(&mut reader)? {
			Ok(ClientMessage::Status) => ServerMessage::Status(SupervisorStatus {
				protocol_version: PROTOCOL_VERSION,
				policy_engine: ComponentStatus::Ready,
				filesystem_broker: ComponentStatus::Ready,
			}),
			_ => ServerMessage::Rejected(RejectionResponse { code: RejectionCode::InvalidRequest }),
		};
		write_message(&mut stream, &response)?;
		Ok(Some(principal_id))
	}
}

fn valid_principal(value: &str) -> bool {
	!value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

fn read_message(reader: &mut impl BufRead) -> Result<Result<ClientMessage, ()>, SupervisorError> {
	let mut line = String::new();
	let size = reader.read_line(&mut line)?;
	if size == 0 || size > MAX_MESSAGE_BYTES || !line.ends_with('\n') {
		return Ok(Err(()));
	}
	Ok(serde_json::from_str(&line).map_err(|_| ()))
}

fn write_message(stream: &mut TcpStream, response: &ServerMessage) -> Result<(), SupervisorError> {
	serde_json::to_writer(&mut *stream, response)?;
	stream.write_all(b"\n")?;
	stream.flush()?;
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::{io::Read, thread};

	fn request(token: &str, principal: &str, version: u16) -> String {
		format!("{{\"kind\":\"handshake\",\"protocol_version\":{version},\"launch_token\":\"{token}\",\"principal_id\":\"{principal}\"}}\n")
	}

	fn run(request: String) -> (Option<String>, String) {
		let supervisor = Supervisor::bind("127.0.0.1:0".parse().expect("address"), "launch-token".to_owned()).expect("supervisor");
		let address = supervisor.local_addr().expect("address");
		let server = thread::spawn(move || supervisor.serve_once().expect("serve"));
		let mut client = TcpStream::connect(address).expect("connect");
		client.write_all(request.as_bytes()).expect("request");
		if request.contains("launch-token") {
			client.write_all(b"{\"kind\":\"status\"}\n").expect("status");
		}
		client.shutdown(std::net::Shutdown::Write).expect("shutdown");
		let mut response = String::new();
		client.read_to_string(&mut response).expect("response");
		(server.join().expect("join"), response)
	}

	#[test]
	fn accepts_an_exact_token_and_binds_the_principal() {
		let (principal, response) = run(request("launch-token", "extension:formatter", PROTOCOL_VERSION));
		assert_eq!(principal, Some("extension:formatter".to_owned()));
		assert!(response.contains("accepted"));
		assert!(response.contains("\"policy_engine\":\"ready\""));
	}

	#[test]
	fn rejects_invalid_token_and_protocol_without_binding_a_principal() {
		let (principal, response) = run(request("wrong", "extension:formatter", PROTOCOL_VERSION));
		assert_eq!(principal, None);
		assert!(response.contains("authentication_failed"));
		let (principal, response) = run(request("launch-token", "extension:formatter", 99));
		assert_eq!(principal, None);
		assert!(response.contains("unsupported_protocol"));
	}
}
