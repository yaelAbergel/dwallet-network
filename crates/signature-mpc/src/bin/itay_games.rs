use std::marker::PhantomData;
use commitment::GroupsPublicParametersAccessors as GroupsPublicParametersAccessors_1;
use enhanced_maurer::encryption_of_discrete_log;
use group::{GroupElement, secp256k1};
// use signature_mpc::twopc_mpc_protocols::validate_proof::validate_proof;
use homomorphic_encryption::{AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors};
use proof::range;
use proof::range::bulletproofs;
use proof::range::bulletproofs::COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS;
use rand_core::OsRng;
use tiresias::{EncryptionKey, LargeBiPrimeSizedNumber};
use twopc_mpc::paillier::CiphertextSpaceGroupElement;
use twopc_mpc::secp256k1::paillier::bulletproofs::{DKGDecentralizedPartyOutput, ProtocolPublicParameters};
use signature_mpc::twopc_mpc_protocols;

use signature_mpc::twopc_mpc_protocols::{encrypt, EncryptedDecentralizedPartySecretKeyShare, EncryptedDecentralizedPartySecretKeyShareValue, generate_keypair, generate_proof, Lang, RANGE_CLAIMS_PER_SCALAR};
use twopc_mpc::secp256k1::SCALAR_LIMBS;
fn main() {
    let public_keyshare_str = "IQJNF3tN3uXYvEk4d8T6/n8nM4eUBKrH01Y9n782tG/cqCECJtydcT3fJoThgYtlMsja1cM4molks7u6RAAYV9HPhFJ/uprz0KiOSlxlanv/1S97RvvGX+yjXMsbJI26r9UZxpFdCRPxZBjrGNfNUEZWbov3btDkZ49ky8v8lXnz/YKpYYjF1iiLa/i4OOpVCf3VIYBLAI0dpN0s/2kLRJLX2M9KCanYNJzuh8lYy7GfZMeid8p/9+NMS4mV83B8eZi79UbfReTEs9A9ZOog84vLDw9zxHvVV8ff6Av+2BJJX1aZRhLbUwCnmq+d421ldNDgEzHdqR33qYC6T0yrWN69611TSyGK3mgqKkiYQwYUoaSXaikbbp2mIk1LE+3y6BJflhwpzFYvIsiEkX9AEOotSIxyxQpKDN7dAGxp1Fz5v/eeRTeL9twuMEhoO/CjbMcEuZXu57UsVCQzSOcGx9Hb/Dm2v4oS4hpbhTZ5vz1ub4M1guzGnFt9eIuXaLXayrT6UclfwygkGtdz7VhsMAb59+WLOGRvJsJ7unKIV+Az6Ip/hd0iAapoQYVSzdWOBVxmrjdYYh1gJ6T4AJSU7PHte/2uOcCmW0G5TyAyeaq5r14PX33o9A0buo6Fusty5LCXGTFRkBurqP/qMorjYo7RCrOrYnVuMU+rMO/w8tvcINdE009rAqASqd6j0SPuE+rEdKmMbpmkGSMBTZKxZokJtj+gJdD+j1d7B3rRcAESBzIwOqo09l4RHOWw1PBvExyDRyEDP9FhKBKWwM7r59OWDuAERSXtejD3RD6IOKfOAPYzFUY=";
    let public_keyshare_bytes = base64::decode(public_keyshare_str).unwrap();
    let res = bcs::from_bytes::<DKGDecentralizedPartyOutput>(&public_keyshare_bytes);
    let centralized_public_keyshare = res.unwrap().public_key_share;

    let secret_keyshare = "62662BC0DD55F09545680B34A2CB005E6821D6C5FBCAA082397C0C712F292AF7";
    let (pub_key, _) = generate_keypair();
    let parsed_keyshare = hex::decode(secret_keyshare).expect("Decoding failed");
    let (proof, commitment_value) = generate_proof(pub_key.clone(), parsed_keyshare.clone());

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

    let public_key_share = group::secp256k1::group_element::GroupElement::new(
        centralized_public_keyshare,
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
    let enhanced_language_public_parameters = twopc_mpc_protocols::enhanced_language_public_parameters::<
        { maurer::SOUND_PROOFS_REPETITIONS },
        RANGE_CLAIMS_PER_SCALAR,
        tiresias::RandomnessSpaceGroupElement,
        Lang,
    >(
        protocol_public_parameters.unbounded_encdl_witness_public_parameters,
        language_public_parameters,
    );
    let res = proof
        .verify(
            &PhantomData,
            &enhanced_language_public_parameters,
            vec![statement],
            &mut OsRng,
        )
        .unwrap();
    println!("{:?}", res);
}

fn important_dont_delete() {
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
}