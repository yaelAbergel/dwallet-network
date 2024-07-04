// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

module dwallet_system::dwallet_transfer {
    use dwallet::object::{Self, UID, ID};
    use dwallet::tx_context::{TxContext};
    use dwallet::transfer;
    use dwallet::tx_context;

    struct PublicKey has key {
        id: UID,
        public_key: vector<u8>,
        key_owner_address: address,
    }

    public fun store_public_key(ctx: &mut TxContext, key: vector<u8>): UID {
        let pk = PublicKey {
            id: object::new(ctx),
            public_key: key,
            key_owner_address: tx_context::sender(ctx),
        };
        let id = pk.id;
        transfer::freeze_object(pk);
        id
    }
}
