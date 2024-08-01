// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#[allow(unused_use)]
module dwallet_system::dwallet_transfer {
    use dwallet::object::{Self, ID, UID};
    use dwallet::transfer;
    use dwallet::tx_context;
    use dwallet::tx_context::TxContext;

    use dwallet_system::dwallet_2pc_mpc_ecdsa_k1::{DWallet, output
    };

    struct PublicKey has key {
        id: UID,
        public_key: vector<u8>,
        key_owner_address: address,
    }

    public fun store_public_key(key: vector<u8>, ctx: &mut TxContext): ID {
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

    // #[allow(unused_variables)]
    public fun transfer_dwallet(
        dwallet: &DWallet,
        public_key: &PublicKey,
        proof: vector<u8>,
        range_proof_commitment_value: vector<u8>,
        encrypted_secret_share: vector<u8>,
        _ctx: &mut TxContext,
    ) {
        let _ = transfer_dwallet_native(
            range_proof_commitment_value,
            proof,
            public_key.public_key,
            encrypted_secret_share,
            output(dwallet),
        );


    }

    #[allow(unused_function)]
    native fun transfer_dwallet_native(
        range_proof_commitment_value: vector<u8>,
        proof: vector<u8>,
        secret_share_public_key: vector<u8>,
        encrypted_secret_share: vector<u8>,
        dwallet_output: vector<u8>,
    ): bool;
}
