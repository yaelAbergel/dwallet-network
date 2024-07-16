use signature_mpc::twopc_mpc_protocols::{encrypt, generate_keypair, generate_proof};
use tiresias::{CiphertextSpaceGroupElement, CiphertextSpaceValue, PaillierModulusSizedNumber};
use twopc_mpc::secp256k1::SCALAR_LIMBS;
use signature_mpc::twopc_mpc_protocols::validate_proof::validate_proof;
// use signature_mpc::twopc_mpc_protocols::validate_proof::validate_proof;

fn main() {
    let keyshare = "62662BC0DD55F09545680B34A2CB005E6821D6C5FBCAA082397C0C712F292AF7";
    let parsed_keyshare = hex::decode(keyshare).expect("Decoding failed");

    // let centralized_public_key = "974";
    // let centralized_public_key = hex::decode(centralized_public_key).expect("Decoding failed");

    let (pub_key, _) = generate_keypair();
    let serialized_encrypted_key = encrypt(parsed_keyshare.clone(), pub_key.clone());
    let proof = generate_proof(pub_key.clone(), parsed_keyshare);
    let encrypted_key: CiphertextSpaceValue = bincode::deserialize(&serialized_encrypted_key).unwrap();
    //
    // let centralized_public_key :PaillierModulusSizedNumber = bincode::deserialize(&centralized_public_key).unwrap();
    // let centralized_public_key = centralized_public_key.into();
    //
    // validate_proof(pub_key, proof, centralized_public_key, encrypted_key);
}
