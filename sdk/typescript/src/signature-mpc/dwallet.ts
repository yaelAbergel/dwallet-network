// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { bcs } from '../bcs/index.js';
import { TransactionBlock, TransactionObjectInput } from '../builder/index.js';
import type { DWalletClient } from '../client/index.js';
import type { Keypair } from '../cryptography/index.js';
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
) => {
	const tx = new TransactionBlock();
	let purePubKey = tx.pure(bcs.vector(bcs.u8()).serialize(public_key));
	tx.moveCall({
		target: `${packageId}::${dWalletModuleName}::store_public_key`,
		arguments: [purePubKey],
		// tx.pure(bcs.vector(bcs.vector(bcs.u8())).serialize(messages))
	});
	await client.signAndExecuteTransactionBlock({
		signer: keypair,
		transactionBlock: tx,
		options: {
			showEffects: true,
		},
	});
};

export const transferDwallet = async (client: DWalletClient, keypair: Keypair) => {
	const tx = new TransactionBlock();
	tx.moveCall({
		target: `${packageId}::dwallet_transfer::transfer_dwallet`,
		arguments: [tx.object('0x184108e30016fdac450079bff0f386b4b3d473b1b16bc30abe1c0a32a1d5c68e')],
		// tx.pure(bcs.vector(bcs.vector(bcs.u8())).serialize(messages))
	});
	await client.signAndExecuteTransactionBlock({
		signer: keypair,
		transactionBlock: tx,
		options: {
			showEffects: true,
		},
	});
};
