use commitment::GroupsPublicParametersAccessors;
use group::GroupElement;
use proof::range;
use proof::range::bulletproofs::COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS;
use proof::range::PublicParametersAccessors;
use tiresias::{LargeBiPrimeSizedNumber, PaillierModulusSizedNumber};
use twopc_mpc::bulletproofs::RangeProof;
use twopc_mpc::secp256k1::paillier::bulletproofs::{ProtocolPublicParameters, SecretKeyShareEncryptionAndProof};

use crate::twopc_mpc_protocols::ProtocolContext;

pub fn validate_proof (dkg_output: &SecretKeyShareEncryptionAndProof<ProtocolContext>, public_key: Vec<u8>, encrypted_secert_key_share: Vec<u8>) {
    let deserialized_encrypted_keyshare = PaillierModulusSizedNumber::from_be_slice(&encrypted_secert_key_share);
    pub const DUMMY_PUBLIC_KEY: LargeBiPrimeSizedNumber = LargeBiPrimeSizedNumber::from_be_hex("97431848911c007fa3a15b718ae97da192e68a4928c0259f2d19ab58ed01f1aa930e6aeb81f0d4429ac2f037def9508b91b45875c11668cea5dc3d4941abd8fbb2d6c8750e88a69727f982e633051f60252ad96ba2e9c9204f4c766c1c97bc096bb526e4b7621ec18766738010375829657c77a23faf50e3a31cb471f72c7abecdec61bdf45b2c73c666aa3729add2d01d7d96172353380c10011e1db3c47199b72da6ae769690c883e9799563d6605e0670a911a57ab5efc69a8c5611f158f1ae6e0b1b6434bafc21238921dc0b98a294195e4e88c173c8dab6334b207636774daad6f35138b9802c1784f334a82cbff480bb78976b22bb0fb41e78fdcb8095");
    let protocol_public_parameters = ProtocolPublicParameters::new(DUMMY_PUBLIC_KEY);
    let range_proof_commitment = range::CommitmentSchemeCommitmentSpaceGroupElement::<
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        {twopc_mpc::secp256k1::bulletproofs::RANGE_CLAIMS_PER_SCALAR},
        RangeProof,
    >::new(
        dkg_output.range_proof_commitment,
        protocol_public_parameters.range_proof_enc_dl_public_parameters.commitment_scheme_public_parameters().commitment_space_public_parameters(),
    );

    let deser_pub_params: tiresias::encryption_key::PublicParameters =
        bincode::deserialize(&public_key).unwrap();

    // let statement = (
    //     range_proof_commitment,
    //     (
    //         deserialized_encrypted_keyshare.clone(),
    //         deser_pub_params,
    //     )
    //         .into(),
    // )
    //     .into();
}
