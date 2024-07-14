use std::marker::PhantomData;
use commitment::{Commitment, GroupsPublicParametersAccessors};
use crypto_bigint::Uint;
use enhanced_maurer::{encryption_of_discrete_log, Proof, StatementSpaceGroupElement};
use group::secp256k1;
use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;
use proof::range;
use proof::range::bulletproofs::{COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, RANGE_CLAIM_BITS};
use proof::range::PublicParametersAccessors;
use rand_core::OsRng;
use tiresias::{LargeBiPrimeSizedNumber, PaillierModulusSizedNumber};
use twopc_mpc::bulletproofs::RangeProof;
use twopc_mpc::paillier::{EncryptionKey, PLAINTEXT_SPACE_SCALAR_LIMBS, UnboundedEncDLWitness};
use twopc_mpc::secp256k1::paillier::bulletproofs::{
    ProtocolPublicParameters, SecretKeyShareEncryptionAndProof,
};

use crate::twopc_mpc_protocols::{enhanced_language_public_parameters, generate_proof, Lang, ProtocolContext, SecretShareProof};
pub use twopc_mpc::secp256k1::{Scalar, SCALAR_LIMBS, GroupElement};

pub const RANGE_CLAIMS_PER_SCALAR: usize =
    Uint::<{ secp256k1::SCALAR_LIMBS }>::BITS / RANGE_CLAIM_BITS;

pub fn validate_proof(
    paillier_public_parameters : Vec<u8>, // public key of the encrypted secret key share
    proof: SecretShareProof, // proof of the encrypted secret key share
    rang_proof_commitment: StatementSpaceGroupElement<
        { maurer::SOUND_PROOFS_REPETITIONS },
        RANGE_CLAIMS_PER_SCALAR,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        tiresias::RandomnessSpaceGroupElement,
        Lang,
    >, // from the encryption
    centralized_party_public_key_share: twopc_mpc::secp256k1::GroupElement, // public key of the decentralized party form the dkg round
    encrypted_secret_key_share: // from the encryption
        <EncryptionKey as AdditivelyHomomorphicEncryptionKey<{ PLAINTEXT_SPACE_SCALAR_LIMBS }>>::CiphertextSpaceGroupElement,
) {

    pub const DUMMY_PUBLIC_KEY: LargeBiPrimeSizedNumber = LargeBiPrimeSizedNumber::from_be_hex("97431848911c007fa3a15b718ae97da192e68a4928c0259f2d19ab58ed01f1aa930e6aeb81f0d4429ac2f037def9508b91b45875c11668cea5dc3d4941abd8fbb2d6c8750e88a69727f982e633051f60252ad96ba2e9c9204f4c766c1c97bc096bb526e4b7621ec18766738010375829657c77a23faf50e3a31cb471f72c7abecdec61bdf45b2c73c666aa3729add2d01d7d96172353380c10011e1db3c47199b72da6ae769690c883e9799563d6605e0670a911a57ab5efc69a8c5611f158f1ae6e0b1b6434bafc21238921dc0b98a294195e4e88c173c8dab6334b207636774daad6f35138b9802c1784f334a82cbff480bb78976b22bb0fb41e78fdcb8095");
    let protocol_public_parameters = ProtocolPublicParameters::new(DUMMY_PUBLIC_KEY);

    let paillier_public_parameters: tiresias::encryption_key::PublicParameters =
        bincode::deserialize(&paillier_public_parameters).unwrap();

    let statement = (
        rang_proof_commitment,
        (
            encrypted_secret_key_share.clone(),
            centralized_party_public_key_share,
        )
        .into(),
    )
        .into();

    let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

    let secp256k1_group_public_parameters = secp256k1::group_element::PublicParameters::default();

    let generator = secp256k1_group_public_parameters.generator;

    let language_public_parameters =
        encryption_of_discrete_log::PublicParameters::<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
        >::new::<PLAINTEXT_SPACE_SCALAR_LIMBS, SCALAR_LIMBS, GroupElement, EncryptionKey>(
            secp256k1_scalar_public_parameters,
            secp256k1_group_public_parameters,
            paillier_public_parameters.clone(),
            generator,
        );

    let unbounded_witness_public_parameters = language_public_parameters
        .randomness_space_public_parameters()
        .clone();

    let enhanced_language_public_parameters = enhanced_language_public_parameters::<
        { maurer::SOUND_PROOFS_REPETITIONS },
        RANGE_CLAIMS_PER_SCALAR,
        tiresias::RandomnessSpaceGroupElement,
        Lang,
    >(
        unbounded_witness_public_parameters,
        language_public_parameters,
    );

    proof.verify(
        &PhantomData,
        &enhanced_language_public_parameters,
        vec![statement],
        &mut OsRng,
    ).unwrap();
}
