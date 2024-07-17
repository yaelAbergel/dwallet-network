use commitment::GroupsPublicParametersAccessors as GroupsPublicParametersAccessors_1;
use group::GroupElement;
// use signature_mpc::twopc_mpc_protocols::validate_proof::validate_proof;
use homomorphic_encryption::{AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors};
use proof::range;
use proof::range::bulletproofs;
use proof::range::bulletproofs::COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS;
use tiresias::LargeBiPrimeSizedNumber;
use twopc_mpc::paillier::CiphertextSpaceGroupElement;
use twopc_mpc::secp256k1::paillier::bulletproofs::ProtocolPublicParameters;

use signature_mpc::twopc_mpc_protocols::{
    encrypt, EncryptedDecentralizedPartySecretKeyShare, EncryptedDecentralizedPartySecretKeyShareValue, generate_keypair,
    generate_proof, RANGE_CLAIMS_PER_SCALAR,
};

fn main() {
    let keyshare = "62662BC0DD55F09545680B34A2CB005E6821D6C5FBCAA082397C0C712F292AF7";
    let parsed_keyshare = hex::decode(keyshare).expect("Decoding failed");

    let (pub_key, _) = generate_keypair();
    let bytes_encrypted_key = encrypt(parsed_keyshare.clone(), pub_key.clone());
    let (proof, commitment_value) = generate_proof(pub_key.clone(), parsed_keyshare);
    let encrypted_key: EncryptedDecentralizedPartySecretKeyShareValue =
        bincode::deserialize(&bytes_encrypted_key).unwrap();
    pub const DUMMY_PUBLIC_KEY: LargeBiPrimeSizedNumber = LargeBiPrimeSizedNumber::from_be_hex("97431848911c007fa3a15b718ae97da192e68a4928c0259f2d19ab58ed01f1aa930e6aeb81f0d4429ac2f037def9508b91b45875c11668cea5dc3d4941abd8fbb2d6c8750e88a69727f982e633051f60252ad96ba2e9c9204f4c766c1c97bc096bb526e4b7621ec18766738010375829657c77a23faf50e3a31cb471f72c7abecdec61bdf45b2c73c666aa3729add2d01d7d96172353380c10011e1db3c47199b72da6ae769690c883e9799563d6605e0670a911a57ab5efc69a8c5611f158f1ae6e0b1b6434bafc21238921dc0b98a294195e4e88c173c8dab6334b207636774daad6f35138b9802c1784f334a82cbff480bb78976b22bb0fb41e78fdcb8095");
    let protocol_public_parameters = ProtocolPublicParameters::new(DUMMY_PUBLIC_KEY);
    let deser_pub_params: tiresias::encryption_key::PublicParameters =
        bincode::deserialize(&pub_key).unwrap();
    let encrypted_secret_share: CiphertextSpaceGroupElement =
        EncryptedDecentralizedPartySecretKeyShare::new(
            encrypted_key,
            deser_pub_params.ciphertext_space_public_parameters(),
        )
        .unwrap();
    let range_proof_commitment = range::CommitmentSchemeCommitmentSpaceGroupElement::<
        { COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
        { RANGE_CLAIMS_PER_SCALAR },
        bulletproofs::RangeProof,
    >::new(
        commitment_value,
        protocol_public_parameters
            .range_proof_enc_dl_public_parameters
            .commitment_scheme_public_parameters
            .commitment_space_public_parameters(),
    )
    .unwrap();
    println!("commitment : {:?}", range_proof_commitment);

    //
    // let centralized_public_key :PaillierModulusSizedNumber = bincode::deserialize(&centralized_public_key).unwrap();
    // let centralized_public_key = centralized_public_key.into();
    //
    // validate_proof(pub_key, proof, centralized_public_key, encrypted_key);
}
