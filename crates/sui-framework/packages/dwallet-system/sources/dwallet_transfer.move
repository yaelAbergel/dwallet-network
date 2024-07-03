// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

module dwallet_system::dwallet_transfer {
    use dwallet::object::{Self, UID};
    use dwallet::tx_context::{TxContext};
    use dwallet::vec_map::{Self, VecMap};
    use dwallet::transfer;

    struct AddressToPublicKeyMap has key {
        map: VecMap<UID, vector<u8>>,
    }

    fun init(ctx: &mut TxContext) {
        transfer::transfer(ShopOwnerCap {
            id: object::new(ctx)
        }, tx_context::sender(ctx));

        // Share the object to make it accessible to everyone!
        transfer::share_object(DonutShop {
            id: object::new(ctx),
            price: 1000,
            balance: balance::zero()
        })
    }

    struct PallierPublicKey has key, store {
        id: UID,
        public_key:vector<u8>,
    }

    public fun create_public_key(ctx: &mut TxContext, public_key: vector<u8>): PallierPublicKey {
        PallierPublicKey {
            id: object::new(ctx),
            public_key,
        }
    }
}
