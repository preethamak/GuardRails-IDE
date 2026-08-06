//! Development launcher for the GuardRails trusted supervisor.

use guardrails_supervisor::Supervisor;
use serde::Serialize;
use std::{env, net::SocketAddr, process::ExitCode};

const LAUNCH_TOKEN_ENV: &str = "GUARDRAILS_SUPERVISOR_LAUNCH_TOKEN";

#[derive(Serialize)]
struct ReadyRecord {
	address: SocketAddr,
}

fn main() -> ExitCode {
	match run() {
		Ok(()) => ExitCode::SUCCESS,
		Err(error) => {
			eprintln!("guardrails supervisor failed: {error}");
			ExitCode::FAILURE
		}
	}
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
	let launch_token = env::var(LAUNCH_TOKEN_ENV).map_err(|_| "missing supervisor launch token")?;
	let supervisor = Supervisor::bind("127.0.0.1:0".parse()?, launch_token)?;
	println!("{}", serde_json::to_string(&ReadyRecord { address: supervisor.local_addr()? })?);
	supervisor.serve_once()?;
	Ok(())
}
