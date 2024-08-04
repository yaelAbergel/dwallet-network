// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { beforeAll, describe, it } from 'vitest';

import {
	approveAndSign,
	createDWallet,
	createPartialUserSignedMessages,
	encrypt,
	generate_keypair,
	generate_proof, getPublicKeyByObjectId,
	init_panic_hook,
	storePublicKey,
	transferDwallet,
	verify_proof
} from "../../src/signature-mpc";
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
		// const [pub_key, _] = generate_keypair();
		// const pubKeyRef = await storePublicKey(pub_key, toolbox.keypair, toolbox.client);

		const publicKeyid = '0x713e40a3e7079fcfa8a5569cf5d4d7a1aef17f08ecb312e517c51a83305530bc';
		const recipientData = await getPublicKeyByObjectId(
			toolbox.client,
			toolbox.keypair,
			publicKeyid,
		);

		init_panic_hook();

		const secretKeyshare = '52FE1C546A99F2BDFE802DBD9382AE0427917399A0950DDC82B8F3E11571A699';
		let parsedKeyshare = Uint8Array.from(Buffer.from(secretKeyshare, 'hex'));
		let encryptedKey = encrypt(parsedKeyshare, recipientData?.public_key!);

		const [proof, encrypted_secret_share, range_commitment] = generate_proof(
			parsedKeyshare,
			encryptedKey,
			recipientData?.public_key!,
		);

		await transferDwallet(
			toolbox.client,
			toolbox.keypair,
			proof,
			encrypted_secret_share,
			range_commitment,
			publicKeyid,
			'0xa0d1cf82b29a60484a76182cc41323aa09fb03634b633107c64b2aa39931f4f3',
			recipientData?.key_owner_address!,
		);
	});
});
