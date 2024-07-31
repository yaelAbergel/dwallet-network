use crate::twopc_mpc_protocols;
use crate::twopc_mpc_protocols::{enhanced_language_public_parameters, Lang, SecretShareProof};
use commitment::GroupsPublicParametersAccessors;
use crypto_bigint::Uint;
use enhanced_maurer::encryption_of_discrete_log::PublicParameters;
use group::{secp256k1, GroupElement};
use homomorphic_encryption::{
    AdditivelyHomomorphicEncryptionKey,
    GroupsPublicParametersAccessors as PublicParametersAccessors,
};
use maurer::SOUND_PROOFS_REPETITIONS;
use proof::range;
use proof::range::bulletproofs;
use proof::range::bulletproofs::{COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, RANGE_CLAIM_BITS};
use rand_core::OsRng;
use std::marker::PhantomData;
use tiresias::CiphertextSpaceGroupElement;
use tiresias::LargeBiPrimeSizedNumber;
use twopc_mpc::secp256k1::paillier::bulletproofs::ProtocolPublicParameters;
pub use twopc_mpc::secp256k1::{Scalar, SCALAR_LIMBS};

pub const RANGE_CLAIMS_PER_SCALAR: usize =
    Uint::<{ secp256k1::SCALAR_LIMBS }>::BITS / RANGE_CLAIM_BITS;

pub const DUMMY_PUBLIC_KEY: LargeBiPrimeSizedNumber = LargeBiPrimeSizedNumber::from_be_hex("97431848911c007fa3a15b718ae97da192e68a4928c0259f2d19ab58ed01f1aa930e6aeb81f0d4429ac2f037def9508b91b45875c11668cea5dc3d4941abd8fbb2d6c8750e88a69727f982e633051f60252ad96ba2e9c9204f4c766c1c97bc096bb526e4b7621ec18766738010375829657c77a23faf50e3a31cb471f72c7abecdec61bdf45b2c73c666aa3729add2d01d7d96172353380c10011e1db3c47199b72da6ae769690c883e9799563d6605e0670a911a57ab5efc69a8c5611f158f1ae6e0b1b6434bafc21238921dc0b98a294195e4e88c173c8dab6334b207636774daad6f35138b9802c1784f334a82cbff480bb78976b22bb0fb41e78fdcb8095");

pub fn public_parameters(
    pub_key: Vec<u8>,
) -> maurer::language::PublicParameters<SOUND_PROOFS_REPETITIONS, Lang> {
    let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

    let secp256k1_group_public_parameters = secp256k1::group_element::PublicParameters::default();

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

pub fn verify_proof(
    public_encryption_key: Vec<u8>,
    proof: SecretShareProof,
    range_proof_commitment_value: range::CommitmentSchemeCommitmentSpaceValue<
        { COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
        { twopc_mpc_protocols::RANGE_CLAIMS_PER_SCALAR },
        bulletproofs::RangeProof,
    >,
    centralized_public_keyshare: group::Value<secp256k1::GroupElement>,
    encrypted_secret_share: Vec<u8>,
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
        unbounded_witness_public_parameters,
        language_public_parameters.clone(),
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

    let ciphertext_space_group_value = bcs::from_bytes(&encrypted_secret_share).unwrap();
    let ciphertext_space_group_element: CiphertextSpaceGroupElement =
        tiresias::CiphertextSpaceGroupElement::new(
            ciphertext_space_group_value,
            language_public_parameters
                .encryption_scheme_public_parameters
                .ciphertext_space_public_parameters(),
        )
        .unwrap();

    let statement = (
        range_proof_commitment,
        (ciphertext_space_group_element, public_key_share.clone()).into(),
    )
        .into();

    proof.verify(
        &PhantomData,
        &enhanced_language_public_parameters,
        vec![statement],
        &mut OsRng,
    )
}

// test mod, check valid proof
#[cfg(test)]
mod tests {
    use super::*;
    use crate::twopc_mpc_protocols::{generate_keypair, generate_proof};
    use enhanced_maurer::encryption_of_discrete_log::StatementAccessors;
    use enhanced_maurer::language::EnhancedLanguageStatementAccessors;
    use twopc_mpc::secp256k1::paillier::bulletproofs::DKGDecentralizedPartyOutput;

    // public_key_share = "025D26C33D01846D86CF204CCA70FB457E66E3B66E11CF67ECA6E93ADF71DC9230";
    const PUBLIC_DKG_OUTPUT: &str = "210264B04A7E32CA125C99C242A75ABFCF26EC6F815B3144A5E43A19AB1BBF1265852103B30BAFA4DB6353F42FBCEC9587373E3508DF986926A05890FDC4AF0ECF8D25B57ECE177918775F5E9CA540D8E0581748DD5FE17C4A8D1E23521A168E65699B7A590A892D34672985E4C35045313BF7F4C622063F9C4699A2C958E085A3FEBB07CEF331D44EE250FEB2D267492FE9B54C979296DFD487CEB8CA461A35DFD65C8B0541CCB7576904BD91A05C1A24E3B3C2506E05292C77045A83A8D4B769AAC3F8324130B609F51FC5F9FB810A25CBF1B4676BF0567F1C8D531ADC3BFDEA29070BC3A6F209F9D5CEEAC061E2DAD75217919252C7841B4D8D19097EC51F427247D09B96034394621FF6AECD40408B15B0820BEFB74928A2CB749E9524016730F0BE78DDCFAEC0F1AD505504F8C7EE29C4D7CE8BBEFF1F2C8C62B4105CD316C42D3D9410A8FD776A8D1885D96BEAE5A37B909147F3762CA18C2C0353AF26817AD36BF09F80E01C53A664904FCEB3AE434465BDAFCAE41384D8762609D659F3ECFC825DD3845B6908E2BD502B828A0D0A36DB326E0BD01ADA06AE0A46AEC3FF736FF8ADF129A0C75EF84106289931CC4A1C8E2812D8ACCC054FA54549B5197B2A5323E29868C6094944C95F60023A7D11464921A5C0C3126604FFC3732E6F84FB619EB6D9ACF01453186DF9B6AE2B4D8EE6666B6907FFAD2A36FA81480A16FF797CD2EE6D51FE3C84C593BB30666B5D7BCD5AC5E6DC8BC88773668049580A216F470E387FA507AB8AEB6719BA99029B77829C52EAADEA14D4DB5231B752FB2EB1A80621025D26C33D01846D86CF204CCA70FB457E66E3B66E11CF67ECA6E93ADF71DC9230";
    const SECRET_KEYSHARE: &str =
        "CA1D77DDAA83254CAE618319F2A916E5081A969D06E9448D97524626D59C2A06";

    #[test]
    fn verify_valid_proof_successfully() {
        let dgk_output = hex::decode(PUBLIC_DKG_OUTPUT).unwrap();
        let dgk_output = bcs::from_bytes::<DKGDecentralizedPartyOutput>(&dgk_output);
        let centralized_party_public_key_share =
            dgk_output.unwrap().centralized_party_public_key_share;
        let discrete_log = hex::decode(SECRET_KEYSHARE).expect("Decoding failed");

        let (encryption_key, _) = generate_keypair();
        let deserialized_pub_params: tiresias::encryption_key::PublicParameters =
            bincode::deserialize(&encryption_key).unwrap();
        let language_public_parameters = public_parameters(encryption_key.clone());

        let (proof, ciphertext_space_group, range_proof_commitment_value) = generate_proof(
            encryption_key.clone(),
            discrete_log.clone(),
            language_public_parameters.clone(),
        );

        // let ciphertext_space_group_value = statements[0].language_statement().encrypted_discrete_log().value();
        let ciphertext_space = bcs::to_bytes(&ciphertext_space_group).unwrap();
        // let deserialized = bcs::from_bytes(&serialized).unwrap();
        // let ciphertext_space: CiphertextSpaceGroupElement  = CiphertextSpaceGroupElement::new(ciphertext_space_group, deserialized_pub_params.ciphertext_space_public_parameters()).unwrap();

        assert!(verify_proof(
            encryption_key,
            proof,
            range_proof_commitment_value,
            centralized_party_public_key_share,
            ciphertext_space
        )
        .is_ok());
    }

    #[test]
    fn call_dwallet_transfer_move() {
        println!("worked")
    }
}
