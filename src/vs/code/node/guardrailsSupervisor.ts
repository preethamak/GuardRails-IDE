/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { spawn } from 'child_process';
import { randomBytes } from 'crypto';
import { createConnection, type Socket } from 'net';
import { hasKey, isObject } from '../../base/common/types.js';

const LAUNCH_TOKEN_ENV = 'GUARDRAILS_SUPERVISOR_LAUNCH_TOKEN';
const READY_LINE_LIMIT = 1024;
const PROTOCOL_VERSION = 1;
const STATUS_REQUEST_TIMEOUT = 5_000;
const ELECTRON_MAIN_PRINCIPAL = 'electron-main';

export interface IGuardRailsSupervisorConnection {
	readonly address: string;
	readonly launchToken: string;
}

interface IReadyRecord {
	readonly address: string;
}

export interface IGuardRailsSupervisorStatus {
	readonly policyEngine: 'ready';
	readonly filesystemBroker: 'ready';
}

export interface IGuardRailsSupervisorChild {
	readonly stdout: NodeJS.ReadableStream | null;
	kill(): boolean;
}

export type GuardRailsSpawn = (command: string, args: readonly string[], options: { readonly env: NodeJS.ProcessEnv; readonly stdio: 'pipe' }) => IGuardRailsSupervisorChild;

export interface IGuardRailsSupervisorBootstrap {
	launchAndReadStatus(executablePath: string, principalId: string): Promise<IGuardRailsSupervisorStatus>;
}

export interface IGuardRailsSupervisorStatusReader {
	getStatus(connection: IGuardRailsSupervisorConnection, principalId: string): Promise<IGuardRailsSupervisorStatus>;
}

/** Launches the trusted supervisor without inheriting the IDE environment. */
export class GuardRailsSupervisorLauncher {

	constructor(
		private readonly spawnSupervisor: GuardRailsSpawn = defaultSpawn,
		private readonly statusReader: IGuardRailsSupervisorStatusReader = new GuardRailsSupervisorClient(),
	) { }

	async launch(executablePath: string): Promise<IGuardRailsSupervisorConnection> {
		return (await this.launchChild(executablePath)).connection;
	}

	async launchAndReadStatus(executablePath: string, principalId: string): Promise<IGuardRailsSupervisorStatus> {
		const launched = await this.launchChild(executablePath);
		try {
			return await this.statusReader.getStatus(launched.connection, principalId);
		} catch (error) {
			launched.child.kill();
			throw error;
		}
	}

	private async launchChild(executablePath: string): Promise<{ readonly child: IGuardRailsSupervisorChild; readonly connection: IGuardRailsSupervisorConnection }> {
		const launchToken = randomBytes(32).toString('hex');
		const child = this.spawnSupervisor(executablePath, [], { env: { [LAUNCH_TOKEN_ENV]: launchToken }, stdio: 'pipe' });
		try {
			const ready = await readReadyRecord(child);
			return { child, connection: { address: ready.address, launchToken } };
		} catch (error) {
			child.kill();
			throw error;
		}
	}
}

/** Electron-main facade that retains supervisor credentials inside the Node process. */
export class GuardRailsSupervisorService {

	constructor(private readonly bootstrap: IGuardRailsSupervisorBootstrap = new GuardRailsSupervisorLauncher()) { }

	initialize(executablePath: string): Promise<IGuardRailsSupervisorStatus> {
		return this.bootstrap.launchAndReadStatus(executablePath, ELECTRON_MAIN_PRINCIPAL);
	}
}

/** Authenticates with the local supervisor and returns its secret-safe state. */
export class GuardRailsSupervisorClient implements IGuardRailsSupervisorStatusReader {

	async getStatus(connection: IGuardRailsSupervisorConnection, principalId: string): Promise<IGuardRailsSupervisorStatus> {
		if (!isPrincipalId(principalId)) {
			throw new Error('supervisor principal identifier is invalid');
		}
		const address = parseLoopbackAddress(connection.address);
		return readStatus(createConnection(address.port, address.host), connection, principalId);
	}
}

function defaultSpawn(command: string, args: readonly string[], options: { readonly env: NodeJS.ProcessEnv; readonly stdio: 'pipe' }): IGuardRailsSupervisorChild {
	return spawn(command, args, options);
}

function readStatus(socket: Socket, connection: IGuardRailsSupervisorConnection, principalId: string): Promise<IGuardRailsSupervisorStatus> {
	return new Promise<IGuardRailsSupervisorStatus>((resolve, reject) => {
		let buffer = '';
		let handshakeAccepted = false;
		let settled = false;
		const timeout = setTimeout(() => settle(() => reject(new Error('supervisor status request timed out'))), STATUS_REQUEST_TIMEOUT);
		const settle = (callback: () => void) => {
			if (settled) {
				return;
			}
			settled = true;
			clearTimeout(timeout);
			socket.off('connect', onConnect);
			socket.off('data', onData);
			socket.off('end', onEnd);
			socket.off('error', onError);
			callback();
		};
		const onConnect = () => socket.write(JSON.stringify({ kind: 'handshake', protocol_version: PROTOCOL_VERSION, launch_token: connection.launchToken, principal_id: principalId }) + '\n');
		const onData = (chunk: Buffer | string) => {
			buffer += String(chunk);
			if (buffer.length > READY_LINE_LIMIT) {
				settle(() => reject(new Error('supervisor response exceeded the size limit')));
				return;
			}
			while (true) {
				const newline = buffer.indexOf('\n');
				if (newline === -1) {
					return;
				}
				const line = buffer.slice(0, newline);
				buffer = buffer.slice(newline + 1);
				try {
					const response: unknown = JSON.parse(line);
					if (!handshakeAccepted) {
						if (!isAcceptedResponse(response, principalId)) {
							throw new Error('supervisor authentication was rejected');
						}
						handshakeAccepted = true;
						socket.write('{"kind":"status"}\n');
						continue;
					}
					if (!isStatusResponse(response)) {
						throw new Error('supervisor status response is invalid');
					}
					socket.end();
					settle(() => resolve({ policyEngine: response.policy_engine, filesystemBroker: response.filesystem_broker }));
					return;
				} catch (error) {
					settle(() => reject(error));
					return;
				}
			}
		};
		const onEnd = () => settle(() => reject(new Error('supervisor exited before returning status')));
		const onError = (error: Error) => settle(() => reject(error));
		socket.once('connect', onConnect);
		socket.on('data', onData);
		socket.once('end', onEnd);
		socket.once('error', onError);
	});
}

async function readReadyRecord(child: IGuardRailsSupervisorChild): Promise<IReadyRecord> {
	const stdout = child.stdout;
	if (!stdout) {
		throw new Error('supervisor did not provide a readiness stream');
	}

	return new Promise<IReadyRecord>((resolve, reject) => {
		let output = '';
		let settled = false;
		const settle = (callback: () => void) => {
			if (settled) {
				return;
			}
			settled = true;
			stdout.off('data', onData);
			stdout.off('end', onEnd);
			stdout.off('error', onError);
			callback();
		};
		const onData = (chunk: Buffer | string) => {
			output += String(chunk);
			if (output.length > READY_LINE_LIMIT) {
				settle(() => reject(new Error('supervisor readiness record exceeded the size limit')));
				return;
			}
			const newline = output.indexOf('\n');
			if (newline === -1) {
				return;
			}
			try {
				const parsed: unknown = JSON.parse(output.slice(0, newline));
				if (!isReadyRecord(parsed)) {
					throw new Error('supervisor readiness record is invalid');
				}
				settle(() => resolve(parsed));
			} catch (error) {
				settle(() => reject(error));
			}
		};
		const onEnd = () => settle(() => reject(new Error('supervisor exited before reporting readiness')));
		const onError = (error: Error) => settle(() => reject(error));
		stdout.on('data', onData);
		stdout.once('end', onEnd);
		stdout.once('error', onError);
	});
}

function isReadyRecord(value: unknown): value is IReadyRecord {
	return typeof value === 'object' && value !== null && 'address' in value && typeof value.address === 'string' && /^127\.0\.0\.1:\d+$/.test(value.address);
}

function parseLoopbackAddress(address: string): { readonly host: '127.0.0.1'; readonly port: number } {
	const match = /^127\.0\.0\.1:(\d+)$/.exec(address);
	if (!match) {
		throw new Error('supervisor address must be an IPv4 loopback address');
	}
	const port = Number(match[1]);
	if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
		throw new Error('supervisor address port is invalid');
	}
	return { host: '127.0.0.1', port };
}

function isPrincipalId(value: string): boolean {
	return value.length > 0 && value.length <= 256 && !/[\u0000-\u001F\u007F]/.test(value);
}

function isAcceptedResponse(value: unknown, principalId: string): boolean {
	return isObject(value)
		&& hasKey(value, { kind: true, protocol_version: true, principal_id: true })
		&& value.kind === 'accepted'
		&& value.protocol_version === PROTOCOL_VERSION
		&& value.principal_id === principalId;
}

function isStatusResponse(value: unknown): value is { readonly policy_engine: 'ready'; readonly filesystem_broker: 'ready' } {
	return isObject(value)
		&& hasKey(value, { kind: true, protocol_version: true, policy_engine: true, filesystem_broker: true })
		&& value.kind === 'status'
		&& value.protocol_version === PROTOCOL_VERSION
		&& value.policy_engine === 'ready'
		&& value.filesystem_broker === 'ready';
}
