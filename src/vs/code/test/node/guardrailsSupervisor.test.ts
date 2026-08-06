/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import assert from 'assert';
import { createServer } from 'net';
import { PassThrough } from 'stream';
import { ensureNoDisposablesAreLeakedInTestSuite } from '../../../base/test/common/utils.js';
import { GuardRailsSupervisorClient, GuardRailsSupervisorLauncher, GuardRailsSupervisorService, type GuardRailsSpawn, type IGuardRailsSupervisorBootstrap, type IGuardRailsSupervisorStatusReader } from '../../node/guardrailsSupervisor.js';

suite('GuardRailsSupervisorLauncher', () => {

	test('passes a new one-time token only to the trusted supervisor', async () => {
		const stdout = new PassThrough();
		let command: string | undefined;
		let environment: NodeJS.ProcessEnv | undefined;
		const launcher = new GuardRailsSupervisorLauncher(((executablePath, _args, options) => {
			command = executablePath;
			environment = options.env;
			queueMicrotask(() => stdout.end('{"address":"127.0.0.1:43123"}\n'));
			return { stdout, kill: () => true };
		}) satisfies GuardRailsSpawn);

		const connection = await launcher.launch('/trusted/guardrails-supervisor');

		assert.strictEqual(command, '/trusted/guardrails-supervisor');
		assert.deepStrictEqual(Object.keys(environment ?? {}), ['GUARDRAILS_SUPERVISOR_LAUNCH_TOKEN']);
		assert.match(connection.launchToken, /^[a-f0-9]{64}$/);
		assert.strictEqual(environment?.GUARDRAILS_SUPERVISOR_LAUNCH_TOKEN, connection.launchToken);
		assert.strictEqual(connection.address, '127.0.0.1:43123');
	});

	test('kills the supervisor when it exits without a readiness record', async () => {
		const stdout = new PassThrough();
		let killCount = 0;
		const launcher = new GuardRailsSupervisorLauncher((() => {
			queueMicrotask(() => stdout.end());
			return { stdout, kill: () => { killCount++; return true; } };
		}) satisfies GuardRailsSpawn);

		await assert.rejects(launcher.launch('/trusted/guardrails-supervisor'), /exited before reporting readiness/);
		assert.strictEqual(killCount, 1);
	});

	test('kills the supervisor when authentication fails after readiness', async () => {
		const stdout = new PassThrough();
		let killCount = 0;
		const launcher = new GuardRailsSupervisorLauncher((() => {
			queueMicrotask(() => stdout.end('{"address":"127.0.0.1:43123"}\n'));
			return { stdout, kill: () => { killCount++; return true; } };
		}) satisfies GuardRailsSpawn, {
			async getStatus() {
				throw new Error('authentication rejected');
			}
		} satisfies IGuardRailsSupervisorStatusReader);

		await assert.rejects(launcher.launchAndReadStatus('/trusted/guardrails-supervisor', 'electron-main'), /authentication rejected/);
		assert.strictEqual(killCount, 1);
	});

	test('reads status only after an authenticated handshake', async () => {
		const server = createServer(socket => {
			let requestCount = 0;
			socket.on('data', chunk => {
				const request = JSON.parse(String(chunk)) as { readonly kind: string; readonly launch_token?: string; readonly principal_id?: string };
				if (requestCount++ === 0) {
					assert.strictEqual(request.kind, 'handshake');
					assert.strictEqual(request.launch_token, 'one-time-token');
					assert.strictEqual(request.principal_id, 'electron-main');
					socket.write('{"kind":"accepted","protocol_version":1,"principal_id":"electron-main"}\n');
					return;
				}
				assert.strictEqual(request.kind, 'status');
				socket.end('{"kind":"status","protocol_version":1,"policy_engine":"ready","filesystem_broker":"ready"}\n');
			});
		});
		await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
		try {
			const address = server.address();
			assert.ok(address && typeof address !== 'string');
			const status = await new GuardRailsSupervisorClient().getStatus({ address: `127.0.0.1:${address.port}`, launchToken: 'one-time-token' }, 'electron-main');
			assert.deepStrictEqual(status, { policyEngine: 'ready', filesystemBroker: 'ready' });
		} finally {
			await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
		}
	});

	test('accepts complete supervisor responses received in one stream chunk', async () => {
		const server = createServer(socket => socket.once('data', () => socket.end('{"kind":"accepted","protocol_version":1,"principal_id":"electron-main"}\n{"kind":"status","protocol_version":1,"policy_engine":"ready","filesystem_broker":"ready"}\n')));
		await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
		try {
			const address = server.address();
			assert.ok(address && typeof address !== 'string');
			const status = await new GuardRailsSupervisorClient().getStatus({ address: `127.0.0.1:${address.port}`, launchToken: 'one-time-token' }, 'electron-main');
			assert.deepStrictEqual(status, { policyEngine: 'ready', filesystemBroker: 'ready' });
		} finally {
			await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
		}
	});

	test('exposes safe status to Electron main without exposing launch credentials', async () => {
		let executablePath: string | undefined;
		let principalId: string | undefined;
		const service = new GuardRailsSupervisorService({
			async launchAndReadStatus(path, principal) {
				executablePath = path;
				principalId = principal;
				return { policyEngine: 'ready', filesystemBroker: 'ready' };
			}
		} satisfies IGuardRailsSupervisorBootstrap);

		const status = await service.initialize('/trusted/guardrails-supervisor');

		assert.strictEqual(executablePath, '/trusted/guardrails-supervisor');
		assert.strictEqual(principalId, 'electron-main');
		assert.deepStrictEqual(status, { policyEngine: 'ready', filesystemBroker: 'ready' });
	});

	ensureNoDisposablesAreLeakedInTestSuite();
});
