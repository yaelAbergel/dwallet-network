use std::marker::PhantomData;

use commitment::GroupsPublicParametersAccessors as GroupsPublicParametersAccessors_1;
use crypto_bigint::{U256, Uint};
use enhanced_maurer::encryption_of_discrete_log::{Language, PublicParameters, StatementAccessors};
use group::{GroupElement, secp256k1};
use homomorphic_encryption::{AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors};
use maurer::SOUND_PROOFS_REPETITIONS;
use proof::range;
use proof::range::bulletproofs;
use proof::range::bulletproofs::COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS;
use rand_core::OsRng;
use tiresias::{LargeBiPrimeSizedNumber, PlaintextSpaceGroupElement};
use twopc_mpc::paillier::CiphertextSpaceGroupElement;
use twopc_mpc::secp256k1::paillier::bulletproofs::{DKGDecentralizedPartyOutput, ProtocolPublicParameters};

use signature_mpc::twopc_mpc_protocols::{encrypt, EncryptedDecentralizedPartySecretKeyShare, enhanced_language_public_parameters, generate_keypair, generate_proof, pad_vector, RANGE_CLAIMS_PER_SCALAR};

pub const DUMMY_PUBLIC_KEY: LargeBiPrimeSizedNumber = LargeBiPrimeSizedNumber::from_be_hex("97431848911c007fa3a15b718ae97da192e68a4928c0259f2d19ab58ed01f1aa930e6aeb81f0d4429ac2f037def9508b91b45875c11668cea5dc3d4941abd8fbb2d6c8750e88a69727f982e633051f60252ad96ba2e9c9204f4c766c1c97bc096bb526e4b7621ec18766738010375829657c77a23faf50e3a31cb471f72c7abecdec61bdf45b2c73c666aa3729add2d01d7d96172353380c10011e1db3c47199b72da6ae769690c883e9799563d6605e0670a911a57ab5efc69a8c5611f158f1ae6e0b1b6434bafc21238921dc0b98a294195e4e88c173c8dab6334b207636774daad6f35138b9802c1784f334a82cbff480bb78976b22bb0fb41e78fdcb8095");
fn main() {
    // let public_keyshare_str = "IQJksEp+MsoSXJnCQqdav88m7G+BWzFEpeQ6GasbvxJlhSEDswuvpNtjU/QvvOyVhzc+NQjfmGkmoFiQ/cSvDs+NJbV+zhd5GHdfXpylQNjgWBdI3V/hfEqNHiNSGhaOZWmbelkKiS00ZymF5MNQRTE79/TGIgY/nEaZoslY4IWj/rsHzvMx1E7iUP6y0mdJL+m1TJeSlt/Uh864ykYaNd/WXIsFQcy3V2kEvZGgXBok47PCUG4FKSx3BFqDqNS3aarD+DJBMLYJ9R/F+fuBCiXL8bRna/BWfxyNUxrcO/3qKQcLw6byCfnVzurAYeLa11IXkZJSx4QbTY0ZCX7FH0JyR9CblgNDlGIf9q7NQECLFbCCC++3SSiiy3SelSQBZzDwvnjdz67A8a1QVQT4x+4pxNfOi77/HyyMYrQQXNMWxC09lBCo/XdqjRiF2Wvq5aN7kJFH83YsoYwsA1OvJoF602vwn4DgHFOmZJBPzrOuQ0Rlva/K5BOE2HYmCdZZ8+z8gl3ThFtpCOK9UCuCig0KNtsybgvQGtoGrgpGrsP/c2/4rfEpoMde+EEGKJkxzEocjigS2KzMBU+lRUm1GXsqUyPimGjGCUlEyV9gAjp9EUZJIaXAwxJmBP/Dcy5vhPthnrbZrPAUUxht+bauK02O5mZraQf/rSo2+oFIChb/eXzS7m1R/jyExZO7MGZrXXvNWsXm3IvIh3NmgElYCiFvRw44f6UHq4rrZxm6mQKbd4KcUuqt6hTU21Ixt1L7LrGoBiECXSbDPQGEbYbPIEzKcPtFfmbjtm4Rz2fspuk633HckjA=";
    let public_keyshare_str = "210264B04A7E32CA125C99C242A75ABFCF26EC6F815B3144A5E43A19AB1BBF1265852103B30BAFA4DB6353F42FBCEC9587373E3508DF986926A05890FDC4AF0ECF8D25B57ECE177918775F5E9CA540D8E0581748DD5FE17C4A8D1E23521A168E65699B7A590A892D34672985E4C35045313BF7F4C622063F9C4699A2C958E085A3FEBB07CEF331D44EE250FEB2D267492FE9B54C979296DFD487CEB8CA461A35DFD65C8B0541CCB7576904BD91A05C1A24E3B3C2506E05292C77045A83A8D4B769AAC3F8324130B609F51FC5F9FB810A25CBF1B4676BF0567F1C8D531ADC3BFDEA29070BC3A6F209F9D5CEEAC061E2DAD75217919252C7841B4D8D19097EC51F427247D09B96034394621FF6AECD40408B15B0820BEFB74928A2CB749E9524016730F0BE78DDCFAEC0F1AD505504F8C7EE29C4D7CE8BBEFF1F2C8C62B4105CD316C42D3D9410A8FD776A8D1885D96BEAE5A37B909147F3762CA18C2C0353AF26817AD36BF09F80E01C53A664904FCEB3AE434465BDAFCAE41384D8762609D659F3ECFC825DD3845B6908E2BD502B828A0D0A36DB326E0BD01ADA06AE0A46AEC3FF736FF8ADF129A0C75EF84106289931CC4A1C8E2812D8ACCC054FA54549B5197B2A5323E29868C6094944C95F60023A7D11464921A5C0C3126604FFC3732E6F84FB619EB6D9ACF01453186DF9B6AE2B4D8EE6666B6907FFAD2A36FA81480A16FF797CD2EE6D51FE3C84C593BB30666B5D7BCD5AC5E6DC8BC88773668049580A216F470E387FA507AB8AEB6719BA99029B77829C52EAADEA14D4DB5231B752FB2EB1A80621025D26C33D01846D86CF204CCA70FB457E66E3B66E11CF67ECA6E93ADF71DC9230";

    let public_keyshare_bytes = hex::decode(public_keyshare_str).unwrap();
    let res = bcs::from_bytes::<DKGDecentralizedPartyOutput>(&public_keyshare_bytes);
    let centralized_public_keyshare = res.unwrap().centralized_party_public_key_share;
    // let public_key_share = "025D26C33D01846D86CF204CCA70FB457E66E3B66E11CF67ECA6E93ADF71DC9230";

    let secret_keyshare = "CA1D77DDAA83254CAE618319F2A916E5081A969D06E9448D97524626D59C2A06";
    let (pub_key, _) = generate_keypair();
    let parsed_keyshare = hex::decode(secret_keyshare).expect("Decoding failed");

    let bytes_encrypted_key = encrypt(parsed_keyshare.clone(), pub_key.clone());

    let deserialized_pub_params: tiresias::encryption_key::PublicParameters =
        bincode::deserialize(&pub_key).unwrap();

    let secp256k1_group_public_parameters = secp256k1::group_element::PublicParameters::default();
    let language_public_parameters = public_parameters(pub_key.clone());
    let protocol_public_parameters = ProtocolPublicParameters::new(DUMMY_PUBLIC_KEY);

    let (proof, statements, commitment_value) = generate_proof(pub_key.clone(), parsed_keyshare.clone(), language_public_parameters.clone());

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

    let encrypted_key  =
        bincode::deserialize(&bytes_encrypted_key).unwrap();

    let encrypted_secret_share_cipher_space: CiphertextSpaceGroupElement =
        EncryptedDecentralizedPartySecretKeyShare::new(
            encrypted_key,
            deserialized_pub_params.ciphertext_space_public_parameters(),
        ).unwrap();

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

    let public_key_share = group::secp256k1::group_element::GroupElement::new(
        centralized_public_keyshare,
        &secp256k1_group_public_parameters,
    )
        .unwrap();

    let statement = (
        range_proof_commitment,
        (encrypted_secret_share_cipher_space ,public_key_share.clone()).into(),
    ).into();


    encrypted_secret_share_cipher_space;
    let a = statements[0].encrypted_discrete_log().value();

    let res = proof
        .verify(
            &PhantomData,
            &enhanced_language_public_parameters,
            statements.clone(),
            &mut OsRng,
        );
    println!("{:?}", res);

    let res = proof
        .verify(
            &PhantomData,
            &enhanced_language_public_parameters,
            vec![statement],
            &mut OsRng,
        );

    println!("{:?}", res);
}

fn public_parameters(pub_key : Vec<u8>) -> maurer::language::PublicParameters<SOUND_PROOFS_REPETITIONS, Lang>
{
    let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

    let secp256k1_group_public_parameters =
        secp256k1::group_element::PublicParameters::default();

    // let paillier_public_parameters =
    //     tiresias::encryption_key::PublicParameters::new(pub_key).unwrap();

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
pub type Lang = Language<
    { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
    { U256::LIMBS },
    secp256k1::GroupElement,
    tiresias::EncryptionKey,
>;
