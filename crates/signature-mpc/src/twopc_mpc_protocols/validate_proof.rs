use crate::twopc_mpc_protocols;
use commitment::GroupsPublicParametersAccessors;
use crypto_bigint::Uint;
use group::secp256k1::group_element::Value;
use group::{secp256k1, GroupElement};
use homomorphic_encryption::{
    AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors as A,
};
use proof::range;
use proof::range::bulletproofs;
use proof::range::bulletproofs::{COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, RANGE_CLAIM_BITS};
use rand_core::OsRng;
use tiresias::{EncryptionKey, LargeBiPrimeSizedNumber};
use twopc_mpc::paillier::CiphertextSpaceGroupElement;
use twopc_mpc::secp256k1::paillier::bulletproofs::ProtocolPublicParameters;
pub use twopc_mpc::secp256k1::{Scalar, SCALAR_LIMBS};

use crate::twopc_mpc_protocols::{encrypt, generate_keypair, generate_proof, EncryptedDecentralizedPartySecretKeyShare, EncryptedDecentralizedPartySecretKeyShareValue, Lang, enhanced_language_public_parameters};
use std::marker::PhantomData;
use enhanced_maurer::encryption_of_discrete_log;

pub const RANGE_CLAIMS_PER_SCALAR: usize =
    Uint::<{ secp256k1::SCALAR_LIMBS }>::BITS / RANGE_CLAIM_BITS;

// fn itay_play(
//     encrypted_decentralized_party_secret_key_share: <EncryptionKey as AdditivelyHomomorphicEncryptionKey<{ PLAINTEXT_SPACE_SCALAR_LIMBS }>>::CiphertextSpaceGroupElement,
//     decentralized_party_public_key_share: &GroupElement,
//     range_proof_commitment: <<RangeProof as RangeProof<{ COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS }>>::CommitmentScheme<{ RANGE_CLAIMS_PER_SCALAR }> as HomomorphicCommitmentScheme<{ COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS }>>::CommitmentSpaceGroupElement)
// -> GroupElement<<<RangeProof as RangeProof<{ COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS }>>::CommitmentScheme<{ RANGE_CLAIMS_PER_SCALAR }> as HomomorphicCommitmentScheme<{ COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS }>>::CommitmentSpaceGroupElement, StatementSpaceGroupElement<{ PLAINTEXT_SPACE_SCALAR_LIMBS }, { SCALAR_LIMBS }, GroupElement, EncryptionKey>>{
//     let statement = (
//         range_proof_commitment,
//         (
//             encrypted_decentralized_party_secret_key_share.clone(),
//             decentralized_party_public_key_share.clone(),
//         )
//             .into(),
//     )
//         .into();
//     statement
// }

// pub fn validate_proof(
//     paillier_public_parameters: Vec<u8>, // public key of the encrypted secret key share
//     proof: SecretShareProof,             // proof of the encrypted secret key share
//     // range_proof_commitment: StatementSpaceGroupElement<
//     //     { maurer::SOUND_PROOFS_REPETITIONS },
//     //     RANGE_CLAIMS_PER_SCALAR,
//     //     COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
//     //     RangeProof,
//     //     tiresias::RandomnessSpaceGroupElement,
//     //     Lang,
//     // >, // from the encryption
//     // centralized_party_public_key_share: group::secp256k1::GroupElement, // public key of the decentralized party form the dkg round
//     encrypted_secret_key_share: <EncryptionKey as AdditivelyHomomorphicEncryptionKey<{ PLAINTEXT_SPACE_SCALAR_LIMBS }>>::CiphertextSpaceGroupElement,
// ) {
//     pub const DUMMY_PUBLIC_KEY: LargeBiPrimeSizedNumber = LargeBiPrimeSizedNumber::from_be_hex("97431848911c007fa3a15b718ae97da192e68a4928c0259f2d19ab58ed01f1aa930e6aeb81f0d4429ac2f037def9508b91b45875c11668cea5dc3d4941abd8fbb2d6c8750e88a69727f982e633051f60252ad96ba2e9c9204f4c766c1c97bc096bb526e4b7621ec18766738010375829657c77a23faf50e3a31cb471f72c7abecdec61bdf45b2c73c666aa3729add2d01d7d96172353380c10011e1db3c47199b72da6ae769690c883e9799563d6605e0670a911a57ab5efc69a8c5611f158f1ae6e0b1b6434bafc21238921dc0b98a294195e4e88c173c8dab6334b207636774daad6f35138b9802c1784f334a82cbff480bb78976b22bb0fb41e78fdcb8095");
//     let protocol_public_parameters = ProtocolPublicParameters::new(DUMMY_PUBLIC_KEY);
//
//     let paillier_public_parameters: tiresias::encryption_key::PublicParameters =
//         bincode::deserialize(&paillier_public_parameters).unwrap();
//     //
//     // let statement = itay_play(
//     //     encrypted_secret_key_share,
//     //     &centralized_party_public_key_share,
//     //     range_proof_commitment,
//     // );
//
//     //
//     // let statement = (
//     //     rang_proof_commitment,
//     //     (
//     //         encrypted_secret_key_share.clone(),
//     //         centralized_party_public_key_share,
//     //     )
//     //     .into(),
//     // )
//     //     .into();
//
//     let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();
//
//     let secp256k1_group_public_parameters = secp256k1::group_element::PublicParameters::default();
//
//     let generator = secp256k1_group_public_parameters.generator;
//
//     let language_public_parameters =
//         encryption_of_discrete_log::PublicParameters::<
//             PLAINTEXT_SPACE_SCALAR_LIMBS,
//             SCALAR_LIMBS,
//             GroupElement,
//             EncryptionKey,
//         >::new::<PLAINTEXT_SPACE_SCALAR_LIMBS, SCALAR_LIMBS, GroupElement, EncryptionKey>(
//             secp256k1_scalar_public_parameters,
//             secp256k1_group_public_parameters,
//             paillier_public_parameters.clone(),
//             generator,
//         );
//
//     let unbounded_witness_public_parameters = language_public_parameters
//         .randomness_space_public_parameters()
//         .clone();
//
//     let enhanced_language_public_parameters = enhanced_language_public_parameters::<
//         { maurer::SOUND_PROOFS_REPETITIONS },
//         RANGE_CLAIMS_PER_SCALAR,
//         tiresias::RandomnessSpaceGroupElement,
//         Lang,
//     >(
//         unbounded_witness_public_parameters,
//         language_public_parameters,
//     );
//
//     // proof
//     //     .verify(
//     //         &PhantomData,
//     //         &enhanced_language_public_parameters,
//     //         vec![statement],
//     //         &mut OsRng,
//     //     )
//     //     .unwrap();
// }

pub fn itay_ide_tricks(public_key_1: Value) {
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
        { twopc_mpc_protocols::RANGE_CLAIMS_PER_SCALAR },
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

    let public_key_share = group::secp256k1::group_element::GroupElement::new(
        public_key_1,
        &protocol_public_parameters.group_public_parameters,
    )
    .unwrap();

    let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

    let secp256k1_group_public_parameters = secp256k1::group_element::PublicParameters::default();

    let generator = secp256k1_group_public_parameters.generator;

    let language_public_parameters =
        encryption_of_discrete_log::PublicParameters::<
            {twopc_mpc::paillier::PLAINTEXT_SPACE_SCALAR_LIMBS},
            SCALAR_LIMBS,
            twopc_mpc::secp256k1::GroupElement,
            EncryptionKey,
        >::new::<{twopc_mpc::paillier::PLAINTEXT_SPACE_SCALAR_LIMBS}, SCALAR_LIMBS, twopc_mpc::secp256k1::GroupElement, EncryptionKey>(
            secp256k1_scalar_public_parameters,
            secp256k1_group_public_parameters,
            protocol_public_parameters.encryption_scheme_public_parameters,
            generator,
        );

    let statement = (range_proof_commitment, (encrypted_secret_share.clone(), public_key_share.clone()).into()).into();
    let enhanced_language_public_parameters = enhanced_language_public_parameters::<
        { maurer::SOUND_PROOFS_REPETITIONS },
        RANGE_CLAIMS_PER_SCALAR,
        tiresias::RandomnessSpaceGroupElement,
        Lang,
    >(
        protocol_public_parameters.unbounded_encdl_witness_public_parameters,
        language_public_parameters,
    );
    proof
        .verify(
            &PhantomData,
            &enhanced_language_public_parameters,
            vec![statement],
            &mut OsRng,
        )
        .unwrap();
}
