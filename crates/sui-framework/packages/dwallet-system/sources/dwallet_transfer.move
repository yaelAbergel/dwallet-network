// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

module dwallet_system::dwallet_transfer {
    use dwallet::object::{Self, UID, ID};
    use dwallet::tx_context::{TxContext};
    use dwallet::transfer;
    use dwallet::tx_context;
    use dwallet_system::dwallet_2pc_mpc_ecdsa_k1::{DWallet};

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

    public fun transfer_dwallet(_wallet: &DWallet) {
        transfer_dwallet_native()
    }

    native fun transfer_dwallet_native();
}
