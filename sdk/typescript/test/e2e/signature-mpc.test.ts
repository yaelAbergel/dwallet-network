// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { beforeAll, describe, it } from 'vitest';

import {
	approveAndSign,
	createDWallet,
	createPartialUserSignedMessages,
	encrypt,
	generate_keypair,
	generate_proof,
	init_panic_hook,
	storePublicKey,
	transferDwallet,
} from '../../src/signature-mpc';
import { setup, TestToolbox } from './utils/setup';

describe('Test signature mpc', () => {
	let toolbox: TestToolbox;

	beforeAll(async () => {
		toolbox = await setup();
	});

	it('the signature mpc create dwallet', async () => {
		console.log(toolbox.keypair.toSuiAddress());
		const dkg = await createDWallet(toolbox.keypair, toolbox.client);

		const bytes: Uint8Array = new TextEncoder().encode('Sign it!!!');

		const signMessagesIdSHA256 = await createPartialUserSignedMessages(
			dkg?.dwalletId!,
			dkg?.dkgOutput,
			[bytes],
			'SHA256',
			toolbox.keypair,
			toolbox.client,
		);
		const sigSHA256 = await approveAndSign(
			dkg?.dwalletCapId!,
			signMessagesIdSHA256!,
			[bytes],
			toolbox.keypair,
			toolbox.client,
		);

		console.log('sigSHA256:');
		console.log(sigSHA256);

		const signMessagesIdKECCAK256 = await createPartialUserSignedMessages(
			dkg?.dwalletId!,
			dkg?.dkgOutput,
			[bytes],
			'KECCAK256',
			toolbox.keypair,
			toolbox.client,
		);
		const sigKECCAK256 = await approveAndSign(
			dkg?.dwalletCapId!,
			signMessagesIdKECCAK256!,
			[bytes],
			toolbox.keypair,
			toolbox.client,
		);

		console.log('sigKECCAK256:');
		console.log(sigKECCAK256);
	});
});

describe('Test key share transfer', () => {
	let toolbox: TestToolbox;

	beforeAll(async () => {
		toolbox = await setup();
	});

	// it('should generate a paillier keypair', async () => {
	// 	const [pub_key, _] = generate_keypair();
	// 	await storePublicKey(pub_key, toolbox.keypair, toolbox.client);
	// 	init_panic_hook();
	// 	let keyshare = '62662BC0DD55F09545680B34A2CB005E6821D6C5FBCAA082397C0C712F292AF7';
	// 	let parsedKeyshare = Uint8Array.from(Buffer.from(keyshare, 'hex'));
	// 	let encryptedKey = encrypt(parsedKeyshare, pub_key);
	// 	let _b = generate_proof(parsedKeyshare, encryptedKey, pub_key);
	// });

	it('should call the transfer_dwallet funcion', async () => {
		await transferDwallet(
			toolbox.client,
			toolbox.keypair,
			'0x184108e30016fdac450079bff0f386b4b3d473b1b16bc30abe1c0a32a1d5c68e',
		);
	});
});
