use crate::twopc_mpc_protocols;
use commitment::GroupsPublicParametersAccessors;
use crypto_bigint::Uint;
use group::{secp256k1, GroupElement};
use homomorphic_encryption::{
    AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors as A,
};
use proof::range;
use proof::range::bulletproofs;
use proof::range::bulletproofs::{COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, RANGE_CLAIM_BITS};
use rand_core::OsRng;
use twopc_mpc::paillier::CiphertextSpaceGroupElement;
use twopc_mpc::secp256k1::paillier::bulletproofs::ProtocolPublicParameters;
pub use twopc_mpc::secp256k1::{Scalar, SCALAR_LIMBS};

use crate::twopc_mpc_protocols::{Lang, enhanced_language_public_parameters, SecretShareProof};
use std::marker::PhantomData;

use commitment::GroupsPublicParametersAccessors as GroupsPublicParametersAccessors_1;
use crypto_bigint::{U256};
use enhanced_maurer::encryption_of_discrete_log::{Language, PublicParameters};
use maurer::SOUND_PROOFS_REPETITIONS;
use tiresias::LargeBiPrimeSizedNumber;

pub const RANGE_CLAIMS_PER_SCALAR: usize =
    Uint::<{ secp256k1::SCALAR_LIMBS }>::BITS / RANGE_CLAIM_BITS;

pub const DUMMY_PUBLIC_KEY: LargeBiPrimeSizedNumber = LargeBiPrimeSizedNumber::from_be_hex("97431848911c007fa3a15b718ae97da192e68a4928c0259f2d19ab58ed01f1aa930e6aeb81f0d4429ac2f037def9508b91b45875c11668cea5dc3d4941abd8fbb2d6c8750e88a69727f982e633051f60252ad96ba2e9c9204f4c766c1c97bc096bb526e4b7621ec18766738010375829657c77a23faf50e3a31cb471f72c7abecdec61bdf45b2c73c666aa3729add2d01d7d96172353380c10011e1db3c47199b72da6ae769690c883e9799563d6605e0670a911a57ab5efc69a8c5611f158f1ae6e0b1b6434bafc21238921dc0b98a294195e4e88c173c8dab6334b207636774daad6f35138b9802c1784f334a82cbff480bb78976b22bb0fb41e78fdcb8095");

pub fn verify_proof(
    public_encryption_key : Vec<u8>,
    proof : SecretShareProof,
    range_proof_commitment_value : range::CommitmentSchemeCommitmentSpaceValue<
        { COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
        { twopc_mpc_protocols::RANGE_CLAIMS_PER_SCALAR },
        bulletproofs::RangeProof,
    >,
    centralized_public_keyshare : group::Value<secp256k1::GroupElement>,
    ciphertext_space_group_element : CiphertextSpaceGroupElement,
) -> enhanced_maurer::Result<()> {
    let secp256k1_group_public_parameters = secp256k1::group_element::PublicParameters::default();
    let language_public_parameters = public_parameters(public_encryption_key);
    let protocol_public_parameters = ProtocolPublicParameters::new(DUMMY_PUBLIC_KEY);

    let unbounded_witness_public_parameters = language_public_parameters
        .randomness_space_public_parameters()
        .clone();

    let enhanced_language_public_parameters = enhanced_language_public_parameters::<
        { SOUND_PROOFS_REPETITIONS },
        RANGE_CLAIMS_PER_SCALAR,
        tiresias::RandomnessSpaceGroupElement,
        Lang,
    >(
        unbounded_witness_public_parameters, //protocol_public_parameters.unbounded_encdl_witness_public_parameters,
        language_public_parameters,
    );

    let range_proof_commitment = range::CommitmentSchemeCommitmentSpaceGroupElement::<
        { COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
        { RANGE_CLAIMS_PER_SCALAR },
        bulletproofs::RangeProof,
    >::new(
        range_proof_commitment_value,
        protocol_public_parameters
            .range_proof_enc_dl_public_parameters
            .commitment_scheme_public_parameters
            .commitment_space_public_parameters(),
    )
        .unwrap();

    let public_key_share = group::secp256k1::group_element::GroupElement::new(
        centralized_public_keyshare,
        &secp256k1_group_public_parameters,
    )
        .unwrap();

    let statement = (
        range_proof_commitment,
        (ciphertext_space_group_element ,public_key_share.clone()).into(),
    ).into();

    proof
        .verify(
            &PhantomData,
            &enhanced_language_public_parameters,
            vec![statement],
            &mut OsRng,
        )

}

pub fn public_parameters(pub_key : Vec<u8>) -> maurer::language::PublicParameters<SOUND_PROOFS_REPETITIONS, Lang>
{
    let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

    let secp256k1_group_public_parameters =
        secp256k1::group_element::PublicParameters::default();

    let paillier_public_parameters: tiresias::encryption_key::PublicParameters =
        bincode::deserialize(&pub_key).unwrap();

    let generator = secp256k1_group_public_parameters.generator;

    PublicParameters::<
        { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
        { secp256k1::SCALAR_LIMBS },
        secp256k1::GroupElement,
        tiresias::EncryptionKey,
    >::new::<
        { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
        { secp256k1::SCALAR_LIMBS },
        secp256k1::GroupElement,
        tiresias::EncryptionKey,
    >(
        secp256k1_scalar_public_parameters,
        secp256k1_group_public_parameters,
        paillier_public_parameters,
        generator,
    )
}