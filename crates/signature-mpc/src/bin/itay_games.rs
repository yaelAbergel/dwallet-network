use signature_mpc::twopc_mpc_protocols::{encrypt, generate_keypair, generate_proof};

fn main() {
    let keyshare = "62662BC0DD55F09545680B34A2CB005E6821D6C5FBCAA082397C0C712F292AF7";
    let parsed_keyshare = hex::decode(keyshare).expect("Decoding failed");
    let (pub_key, _) = generate_keypair();
    // let encryptedKey = encrypt(parsed_keyshare, pub_key);
    generate_proof(pub_key, parsed_keyshare)
}
