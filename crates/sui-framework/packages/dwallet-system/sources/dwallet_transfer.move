module dwallet_system::dwallet_transfer {
    use dwallet::object::{Self, UID};
    use dwallet::tx_context::{TxContext};

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
