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

describe('Test key share transfer', () => {
	let toolbox: TestToolbox;

	beforeAll(async () => {
		toolbox = await setup();
	});

	it('should generate a paillier keypair', async () => {
		const [pub_key, _] = generate_keypair();
		await storePublicKey(pub_key, toolbox.keypair, toolbox.client);
		init_panic_hook();

		const keyshare = '62662BC0DD55F09545680B34A2CB005E6821D6C5FBCAA082397C0C712F292AF7';
		let parsedKeyshare = Uint8Array.from(Buffer.from(keyshare, 'hex'));
		let encryptedKey = encrypt(parsedKeyshare, pub_key);

		const [proof, ciphertext_space, range_commitment] = generate_proof(
			parsedKeyshare,
			encryptedKey,
			pub_key,
		);

		verify_proof(proof, ciphertext_space, range_commitment);
	});

	it('should call the transfer_dwallet funcion', async () => {
		await transferDwallet(toolbox.client, toolbox.keypair);
	});

	// IQJNF3tN3uXYvEk4d8T6/n8nM4eUBKrH01Y9n782tG/cqCECJtydcT3fJoThgYtlMsja1cM4molks7u6RAAYV9HPhFJ/uprz0KiOSlxlanv/1S97RvvGX+yjXMsbJI26r9UZxpFdCRPxZBjrGNfNUEZWbov3btDkZ49ky8v8lXnz/YKpYYjF1iiLa/i4OOpVCf3VIYBLAI0dpN0s/2kLRJLX2M9KCanYNJzuh8lYy7GfZMeid8p/9+NMS4mV83B8eZi79UbfReTEs9A9ZOog84vLDw9zxHvVV8ff6Av+2BJJX1aZRhLbUwCnmq+d421ldNDgEzHdqR33qYC6T0yrWN69611TSyGK3mgqKkiYQwYUoaSXaikbbp2mIk1LE+3y6BJflhwpzFYvIsiEkX9AEOotSIxyxQpKDN7dAGxp1Fz5v/eeRTeL9twuMEhoO/CjbMcEuZXu57UsVCQzSOcGx9Hb/Dm2v4oS4hpbhTZ5vz1ub4M1guzGnFt9eIuXaLXayrT6UclfwygkGtdz7VhsMAb59+WLOGRvJsJ7unKIV+Az6Ip/hd0iAapoQYVSzdWOBVxmrjdYYh1gJ6T4AJSU7PHte/2uOcCmW0G5TyAyeaq5r14PX33o9A0buo6Fusty5LCXGTFRkBurqP/qMorjYo7RCrOrYnVuMU+rMO/w8tvcINdE009rAqASqd6j0SPuE+rEdKmMbpmkGSMBTZKxZokJtj+gJdD+j1d7B3rRcAESBzIwOqo09l4RHOWw1PBvExyDRyEDP9FhKBKWwM7r59OWDuAERSXtejD3RD6IOKfOAPYzFUY=

	// it('should transfer dwallet', async () => {
	// 	// generate the keypair Bob
	// 	const [pub_key, _] = generate_keypair();
	// 	await storePublicKey(pub_key, toolbox.keypair, toolbox.client);
	//
	// 	init_panic_hook();
	//
	// 	// some key share from configuration Alice
	// 	let keyshare_to_encrypt = '62662BC0DD55F09545680B34A2CB005E6821D6C5FBCAA082397C0C712F292AF7';
	// 	let parsedKeyshare = Uint8Array.from(Buffer.from(keyshare_to_encrypt, 'hex'));
	// 	let centeralized_public_key = 'insert the centralized public key here';
	//
	// 	// encrypt the secret key share
	// 	let encryptedKey = encrypt(parsedKeyshare, pub_key);
	//
	// 	// generate the proof
	// 	let [proof, commitment] = generate_proof(parsedKeyshare, encryptedKey, pub_key);
	//
	// 	// verify the proof
	// 	validate_proof(pub_key, proof, commitment, centeralized_public_key, encryptedKey);
	// });
});
