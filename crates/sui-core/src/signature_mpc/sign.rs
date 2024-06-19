// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use sui_types::messages_signature_mpc::SignatureMPCSessionID;
use std::collections::{HashMap, HashSet};
use rand::rngs::OsRng;
use sui_types::base_types::{EpochId, ObjectRef};
use signature_mpc::twopc_mpc_protocols::{AdditivelyHomomorphicDecryptionKeyShare, GroupElement, PartyID, Result, DecryptionPublicParameters, DKGDecentralizedPartyOutput, DecentralizedPartyPresign, initiate_decentralized_party_sign, SecretKeyShareSizedNumber, message_digest, PublicNonceEncryptedPartialSignatureAndProof, DecryptionKeyShare, AdjustedLagrangeCoefficientSizedNumber, decrypt_signature_decentralized_party_sign, PaillierModulusSizedNumber, ProtocolContext, Commitment, SignatureThresholdDecryptionParty, Value, Hash, generate_proof};
use std::convert::TryInto;
use std::mem;
use tracing::error;

#[derive(Default)]
pub(crate) enum SignRound {
    FirstRound {
        signature_threshold_decryption_round_parties: Vec<SignatureThresholdDecryptionParty>
    },
    IdentifiableAbortFirstRound,
    IdentifiableAbortSecondRound,
    #[default]
    None,
}

impl SignRound {
    pub(crate) fn new(
        tiresias_public_parameters: DecryptionPublicParameters,
        tiresias_key_share_decryption_key_share: SecretKeyShareSizedNumber,
        epoch: EpochId,
        party_id: PartyID,
        parties: HashSet<PartyID>,
        session_id: SignatureMPCSessionID,
        messages: Vec<Vec<u8>>,
        dkg_output: DKGDecentralizedPartyOutput,
        public_nonce_encrypted_partial_signature_and_proofs: Vec<PublicNonceEncryptedPartialSignatureAndProof<ProtocolContext>>,
        presigns: Vec<DecentralizedPartyPresign>,
        hash: Hash,
    ) -> Result<(Self, Vec<(PaillierModulusSizedNumber, PaillierModulusSizedNumber)>)> {
        let sign_mpc_party_per_message = initiate_decentralized_party_sign(
            tiresias_key_share_decryption_key_share,
            tiresias_public_parameters.clone(),
            //epoch,
            party_id,
            parties.clone(),
            //session_id,
            dkg_output,
            presigns.clone(),
        )?;

        let (decryption_shares, signature_threshold_decryption_round_parties): (Vec<_>, Vec<_>) = messages.iter().zip(sign_mpc_party_per_message.into_iter()).zip(public_nonce_encrypted_partial_signature_and_proofs.clone().into_iter()).map(|((m, party), public_nonce_encrypted_partial_signature_and_proof)| {
            let m = message_digest(m, &hash);
            party
                .partially_decrypt_encrypted_signature_parts_prehash(
                    m,
                    public_nonce_encrypted_partial_signature_and_proof,
                    &mut OsRng,
                )
        }).collect::<Result<Vec<((PaillierModulusSizedNumber, PaillierModulusSizedNumber), SignatureThresholdDecryptionParty)>>>()?.into_iter().unzip();

        let mut v = decryption_shares.clone();
        if party_id == 1 {
            v[0] = (PaillierModulusSizedNumber::from_u16(200), PaillierModulusSizedNumber::from_u16(200));
        }
        println!("logilog: {:?}", party_id);
        Ok((
            SignRound::FirstRound {
                signature_threshold_decryption_round_parties
            },
            v
        ))
    }

    pub(crate) fn complete_round(
        &mut self,
        state: SignState,
    ) -> Result<SignRoundCompletion> {
        let round = mem::take(self);
        match round {
            SignRound::FirstRound { signature_threshold_decryption_round_parties } => {
                let decrypt_result = decrypt_signature_decentralized_party_sign(
                    state.messages.unwrap(),
                    state.tiresias_public_parameters.clone(),
                    state.decryption_shares.clone(),
                    state.public_nonce_encrypted_partial_signature_and_proofs.clone().unwrap(),
                    signature_threshold_decryption_round_parties,
                );

                if decrypt_result.failed_messages_indices.len() == 0 {
                    Ok(SignRoundCompletion::SignatureOutput(decrypt_result.messages_signatures))
                } else {
                    // TODO: Generate and send proof
                    // create the decryption key share
                    let decryption_key_share = DecryptionKeyShare::new(
                        state.party_id,
                        state.tiresias_key_share_decryption_key_share,
                        &state.tiresias_public_parameters,
                    )?;
                    // generate the proof

                    let (proof, party) = generate_proof(
                        state.tiresias_public_parameters.clone(),
                        decryption_key_share,
                        state.party_id,
                        _,
                        state.tiresias_public_parameters.encryption_scheme_public_parameters,
                        _,
                    );
                    Ok(SignRoundCompletion::ProofOutput(vec![vec![7, 8, 9]]))
                }
            }

            SignRound::IdentifiableAbortFirstRound => {
                println!("recv wohwoh: IdentifiableAbortFirstRound message");
                Ok(SignRoundCompletion::None)
            }
            _ => {
                Ok(SignRoundCompletion::None)
            }
        }
    }
}


pub(crate) enum SignRoundCompletion {
    SignatureOutput(Vec<Vec<u8>>),
    ProofOutput(PartyID, DecryptionKeyShare::PartialDecryptionProof),
    None,
}

#[derive(Clone)]
pub(crate) struct SignState {
    epoch: EpochId,
    party_id: PartyID,
    parties: HashSet<PartyID>,
    aggregator_party_id: PartyID,
    tiresias_public_parameters: DecryptionPublicParameters,
    tiresias_key_share_decryption_key_share: SecretKeyShareSizedNumber,
    messages: Option<Vec<Vec<u8>>>,
    public_nonce_encrypted_partial_signature_and_proofs: Option<Vec<PublicNonceEncryptedPartialSignatureAndProof<ProtocolContext>>>,
    presign: DecentralizedPartyPresign,
    decryption_shares: HashMap<PartyID, Vec<(PaillierModulusSizedNumber, PaillierModulusSizedNumber)>>,
}

impl SignState {
    pub(crate) fn new(
        tiresias_key_share_decryption_key_share: SecretKeyShareSizedNumber,
        tiresias_public_parameters: DecryptionPublicParameters,
        epoch: EpochId,
        party_id: PartyID,
        parties: HashSet<PartyID>,
        session_id: SignatureMPCSessionID,
        presign: DecentralizedPartyPresign,
    ) -> Self {
        let aggregator_party_id = ((u64::from_be_bytes((&session_id.0[0..8]).try_into().unwrap()) % parties.len() as u64) + 1) as PartyID;

        Self {
            epoch,
            party_id,
            parties,
            aggregator_party_id,
            tiresias_public_parameters,
            messages: None,
            public_nonce_encrypted_partial_signature_and_proofs: None,
            decryption_shares: HashMap::new(),
            tiresias_key_share_decryption_key_share,
            presign,
        }
    }

    pub(crate) fn set(
        &mut self,
        messages: Vec<Vec<u8>>,
        public_nonce_encrypted_partial_signature_and_proofs: Vec<PublicNonceEncryptedPartialSignatureAndProof<ProtocolContext>>,
    ) {
        self.messages = Some(messages);
        self.public_nonce_encrypted_partial_signature_and_proofs = Some(public_nonce_encrypted_partial_signature_and_proofs);
    }

    pub(crate) fn insert_first_round(
        &mut self,
        party_id: PartyID,
        message: Vec<(PaillierModulusSizedNumber, PaillierModulusSizedNumber)>,
    ) -> Result<()> {
        let _ = self
            .decryption_shares
            .insert(party_id, message);
        Ok(())
    }

    pub(crate) fn ready_for_complete_first_round(&self, round: &SignRound) -> bool {
        match round {
            SignRound::FirstRound { .. } if self.decryption_shares.len() == self.parties.len() && self.party_id == self.aggregator_party_id => true,
            SignRound::IdentifiableAbortFirstRound => true, // TODO: this is probably not correct
            _ => false
        }
    }
}
