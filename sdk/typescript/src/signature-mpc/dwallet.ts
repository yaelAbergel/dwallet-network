// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { bcs } from '../bcs/index.js';
import { TransactionBlock } from '../builder/index.js';
import type { DWalletClient } from '../client/index.js';
import type { Keypair } from '../cryptography/index.js';
import { SuiObjectRef } from '../types';
import { fetchObjectBySessionId } from './utils.js';

const packageId = '0x3';
const dWalletModuleName = 'dwallet';
const dWallet2PCMPCECDSAK1ModuleName = 'dwallet_2pc_mpc_ecdsa_k1';

export async function approveAndSign(
	dwalletCapId: string,
	signMessagesId: string,
	messages: Uint8Array[],
	keypair: Keypair,
	client: DWalletClient,
) {
	const tx = new TransactionBlock();
	const [messageApprovals] = tx.moveCall({
		target: `${packageId}::${dWalletModuleName}::approve_messages`,
		arguments: [
			tx.object(dwalletCapId),
			tx.pure(bcs.vector(bcs.vector(bcs.u8())).serialize(messages)),
		],
	});
	tx.moveCall({
		target: `${packageId}::${dWalletModuleName}::sign`,
		typeArguments: [
			`${packageId}::${dWallet2PCMPCECDSAK1ModuleName}::SignData`,
			`${packageId}::${dWallet2PCMPCECDSAK1ModuleName}::NewSignDataEvent`,
		],
		arguments: [tx.object(signMessagesId), messageApprovals],
	});
	const result = await client.signAndExecuteTransactionBlock({
		signer: keypair,
		transactionBlock: tx,
		options: {
			showEffects: true,
		},
	});

	const signSessionRef = result.effects?.created?.filter((o) => o.owner === 'Immutable')[0]
		.reference!;

	const signOutput = await fetchObjectBySessionId(
		signSessionRef.objectId,
		`${packageId}::${dWalletModuleName}::SignOutput`,
		keypair,
		client,
	);

	const fields =
		signOutput?.dataType === 'moveObject'
			? (signOutput.fields as {
					id: { id: string };
					signatures: number[][];
			  })
			: null;

	return fields
		? {
				signOutputId: fields.id.id,
				signatures: fields.signatures,
		  }
		: null;
}

export const storePublicKey = async (
	public_key: Uint8Array,
	keypair: Keypair,
	client: DWalletClient,
): Promise<SuiObjectRef> => {
	const tx = new TransactionBlock();
	let purePubKey = tx.pure(bcs.vector(bcs.u8()).serialize(public_key));
	tx.moveCall({
		target: `${packageId}::${dWalletModuleName}::store_public_key`,
		arguments: [purePubKey],
	});
	let result = await client.signAndExecuteTransactionBlock({
		signer: keypair,
		transactionBlock: tx,
		options: {
			showEffects: true,
		},
	});
	return result.effects?.created?.filter((o) => o.owner === 'Immutable')[0].reference!;
};

export const transferDwallet = async (
	client: DWalletClient,
	keypair: Keypair,
	proof,
	encrypted_secret_share,
	range_commitment,
	publicKeyObjID,
	dwalletID,
) => {
	const tx = new TransactionBlock();
	// let parseArg1 = parseArg(proof, tx);
	let parseArg2 = parseArg(range_commitment, tx);
	let parseArg3 = parseArg(encrypted_secret_share, tx);
	tx.moveCall({
		target: `${packageId}::dwallet_transfer::transfer_dwallet`,
		arguments: [
			tx.object(dwalletID),
			tx.object(publicKeyObjID),
			tx.pure(proof),
			parseArg2,
			parseArg3,
		],
	});
	await client.signAndExecuteTransactionBlock({
		signer: keypair,
		transactionBlock: tx,
		options: {
			showEffects: true,
		},
	});
};

const parseArg = (arg, tx) => tx.pure(bcs.vector(bcs.u8()).serialize(arg));
