use signature_mpc::twopc_mpc_protocols::{encrypt, generate_keypair, generate_proof};
use signature_mpc::twopc_mpc_protocols::validate_proof::validate_proof;

fn main() {
    let keyshare = "62662BC0DD55F09545680B34A2CB005E6821D6C5FBCAA082397C0C712F292AF7";
    let parsed_keyshare = hex::decode(keyshare).expect("Decoding failed");
    let centralized_public_key = "974";
    let centralized_public_key = hex::decode(centralized_public_key).expect("Decoding failed");
    let (pub_key, _) = generate_keypair();
    let encryptedKey = encrypt(parsed_keyshare.clone(), pub_key.clone());
    let (proof, commitment) = generate_proof(pub_key.clone(), parsed_keyshare);

    let encryptedKey = bincode::deserialize(&encryptedKey).unwrap();
    let centralized_public_key = bincode::deserialize(& centralized_public_key).unwrap();
    validate_proof(pub_key, proof, commitment, encryptedKey, centralized_public_key);
}
