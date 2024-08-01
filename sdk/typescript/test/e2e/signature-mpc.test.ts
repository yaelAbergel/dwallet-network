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

describe('Test key share transfer', () => {
	let toolbox: TestToolbox;

	beforeAll(async () => {
		toolbox = await setup();
	});

	it('should generate a paillier keypair', async () => {
		const dkg = await createDWallet(toolbox.keypair, toolbox.client);
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

		await transferDwallet(
			toolbox.client,
			toolbox.keypair,
			proof,
			encrypted_secret_share,
			range_commitment,
			pubKeyRef.objectId,
			dkg?.dwalletId!,
		);
	});
});
