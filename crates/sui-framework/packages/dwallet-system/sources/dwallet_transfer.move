module dwallet_system::dwallet_transfer {
    use dwallet::object::{Self, UID, ID};
    struct PallierPublicKey has key, store {
        id: UID,
        public_key:vector<u8>,
    }
}
