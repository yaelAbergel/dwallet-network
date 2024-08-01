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
	verify_proof,
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

describe('Create dwallet', () => {
	let toolbox: TestToolbox;

	beforeAll(async () => {
		toolbox = await setup();
	});

	it('the signature mpc create dwallet', async () => {
		console.log(toolbox.keypair.toSuiAddress());
		const dkg = await createDWallet(toolbox.keypair, toolbox.client);
		console.log({ dkg });
	});
});

describe('Create public key', () => {
	let toolbox: TestToolbox;

	beforeAll(async () => {
		toolbox = await setup();
	});

	it('the signature mpc create dwallet', async () => {
		const [pub_key, _] = generate_keypair();
		const pubKeyRef = await storePublicKey(pub_key, toolbox.keypair, toolbox.client);
		console.log({ pubKeyRef });
	});
});

describe('Test key share transfer', () => {
	let toolbox: TestToolbox;

	beforeAll(async () => {
		toolbox = await setup();
	});

	it('should generate a paillier keypair', async () => {
		const [pub_key, _] = generate_keypair();
		const pubKeyRef = await storePublicKey(pub_key, toolbox.keypair, toolbox.client);
		init_panic_hook();

		const keyshare = '3BD79BA7B3D6C5022FD97AE4578DBAF3C4F42A05FE45EB173E696FE7D21E499B';
		let parsedKeyshare = Uint8Array.from(Buffer.from(keyshare, 'hex'));
		let encryptedKey = encrypt(parsedKeyshare, pub_key);

		const [proof, encrypted_secret_share, range_commitment] = generate_proof(
			parsedKeyshare,
			encryptedKey,
			pub_key,
		);
		// await new Promise(resolve => setTimeout(resolve, 10_000));

		await transferDwallet(
			toolbox.client,
			toolbox.keypair,
			proof,
			encrypted_secret_share,
			range_commitment,
			'0x8ddbeb2c97bfc7fa43977b12e30f1d08f1e7020b01013d06da50fedb43e84531',
			'0x85b031c23f38690a41e6e0972e3f2be5ef09a6dafd3f20d67e881e69efe83535',
		);
	});
});
