// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

module dwallet_system::dwallet_transfer {
    use dwallet::object::{Self, UID};
    use dwallet::tx_context::{TxContext};
    use dwallet::vec_map::{VecMap};
    use dwallet::transfer;

    struct AddressToPublicKeyMap has key {
        id: UID,
        map: VecMap<UID, vector<u8>>,
    }

    fun init(ctx: &mut TxContext) {
        transfer::share_object(AddressToPublicKeyMap {
            id: object::new(ctx),
            map: VecMap::new()
        })
    }

    struct PallierPublicKey has key, store {
        id: UID,
        public_key: vector<u8>,
    }

    public fun create_public_key(ctx: &mut TxContext, public_key: vector<u8>): PallierPublicKey {
        PallierPublicKey {
            id: object::new(ctx),
            public_key,
        }
    }
}
