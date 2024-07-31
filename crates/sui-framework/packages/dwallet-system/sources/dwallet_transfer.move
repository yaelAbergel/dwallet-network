// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

module dwallet_system::dwallet_transfer {
    use dwallet::object::{Self, ID, UID};
    use dwallet::transfer;
    use dwallet::tx_context;
    use dwallet::tx_context::TxContext;

    use dwallet_system::dwallet_2pc_mpc_ecdsa_k1::{DWallet, output
    };

    //commitment_to_centralized_party_secret_key_share,
    //         DKGSession
    struct PublicKey has key {
        id: UID,
        public_key: vector<u8>,
        key_owner_address: address,
    }

    public fun store_public_key(ctx: &mut TxContext, key: vector<u8>): ID {
        let pk = PublicKey {
            id: object::new(ctx),
            public_key: key,
            key_owner_address: tx_context::sender(ctx),
        };
        let pk_id = object::id(&pk);
        transfer::freeze_object(pk);
        pk_id
    }

    public fun get_public_key(public_key: &PublicKey): &PublicKey {
        public_key
    }

    public fun transfer_dwallet(
        dwallet: &DWallet,
        proof: vector<u8>,
        range_proof_commitment_value: vector<u8>,
        // public_key: &PublicKey,
        encrypted_secret_share: vector<u8>,
    ) {
        transfer_dwallet_native(
            proof,
            range_proof_commitment_value,
            // public_key.public_key,
            encrypted_secret_share,
            output(dwallet),
        );
    }

    native fun transfer_dwallet_native(
        proof: vector<u8>,
        range_proof_commitment_value: vector<u8>,
        // secret_share_public_key: vector<u8>,
        encrypted_secret_share: vector<u8>,
        dwallet_output: vector<u8>,
    );
}
