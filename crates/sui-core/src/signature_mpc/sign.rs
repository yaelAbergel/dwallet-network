// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use sui_types::messages_signature_mpc::SignatureMPCSessionID;
use std::collections::{HashMap, HashSet};
use rand::rngs::OsRng;
use sui_types::base_types::{EpochId, ObjectRef};
use signature_mpc::twopc_mpc_protocols::{AdditivelyHomomorphicDecryptionKeyShare, GroupElement, PartyID, Result, DecryptionPublicParameters, DKGDecentralizedPartyOutput, DecentralizedPartyPresign, initiate_decentralized_party_sign, SecretKeyShareSizedNumber, message_digest, PublicNonceEncryptedPartialSignatureAndProof, DecryptionKeyShare, AdjustedLagrangeCoefficientSizedNumber, decrypt_signature_decentralized_party_sign, PaillierModulusSizedNumber, ProtocolContext, Commitment, SignatureThresholdDecryptionParty, Value, Hash, generate_proof, signature_partial_decryption_verification_round, identify_malicious_parties, PartialDecryptionProof, ProofParty};
use std::convert::TryInto;
use std::mem;
use futures::StreamExt;
use itertools::Itertools;
use tracing::error;

#[derive(Default)]
pub(crate) enum SignRound {
    FirstRound {
        signature_threshold_decryption_round_parties: Vec<SignatureThresholdDecryptionParty>
    },
    IdentifiableAbortFirstRound
    // party_id: PartyID,
    // proofs : Vec<DecryptionKeyShare::PartialDecryptionProof>
    ,
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
        Ok((
            SignRound::FirstRound {
                signature_threshold_decryption_round_parties
            },
            v
        ))
    }

    fn generate_proofs(
        &mut self,
        state: &SignState,
        failed_messages_indices: &Vec<usize>,
    ) -> Vec<(PartialDecryptionProof, ProofParty)> {
        let decryption_key_share = DecryptionKeyShare::new(
            state.party_id,
            state.tiresias_key_share_decryption_key_share,
            &state.tiresias_public_parameters,
        ).unwrap();

        failed_messages_indices.iter().map(
            |index| {
                generate_proof(
                    state.tiresias_public_parameters.clone(),
                    decryption_key_share.clone(),
                    state.party_id,
                    state.presigns.clone().unwrap().get(*index).unwrap().clone(),
                    state.tiresias_public_parameters.encryption_scheme_public_parameters.clone(),
                    state
                        .public_nonce_encrypted_partial_signature_and_proofs.clone().unwrap().get(*index).unwrap().clone(),
                )
            }).collect()
    }

    pub(crate) fn complete_round(
        &mut self,
        state: &mut SignState,
    ) -> Result<SignRoundCompletion> {
        let round = mem::take(self);
        match round {
            SignRound::FirstRound { signature_threshold_decryption_round_parties } => {
                let decrypt_result = decrypt_signature_decentralized_party_sign(
                    state.messages.clone().unwrap(),
                    state.tiresias_public_parameters.clone(),
                    state.decryption_shares.clone(),
                    state.public_nonce_encrypted_partial_signature_and_proofs.clone().unwrap(),
                    signature_threshold_decryption_round_parties,
                );

                if decrypt_result.failed_messages_indices.is_empty() {
                    return Ok(SignRoundCompletion::SignatureOutput(decrypt_result.messages_signatures));
                }

                // TODO: Generate and send proof
                state.failed_messages_indices = Some(decrypt_result.failed_messages_indices.clone());
                let proofs_tuples = self.generate_proofs(
                    &state, &decrypt_result.failed_messages_indices);
                // map the proofs_tuples, a vector of tuples, to a vector of proofs, the first element in each tuple
                let proofs = proofs_tuples.iter().map(|(proof, _)| proof.clone()).collect();
                let proofs_map = HashMap::from([(state.party_id, proofs)]);
                state.proofs = Some(proofs_map);

                // TODO: Send proof to all parties
                // Data we need to send to other parties: party_id, HashMap(message_index, proof)
                //
                Ok(SignRoundCompletion::ProofsMessage())
            }

            SignRound::IdentifiableAbortFirstRound=> {
                // what other validations we need to check?
                if state.proofs.clone().unwrap().len() != state.parties.len() {
                    println!("waiting for all proofs to be received, recv {:?}", state.clone().proofs.unwrap().keys());
                    // print the parties len
                    println!("parties len: {}", state.parties.len());
                    return Ok(SignRoundCompletion::None); // TODO: handle this case
                }
                // start the second round

                println!("received all proofs, starting second round");
                let proof_results = self.generate_proofs(
                    &state, &state.failed_messages_indices.clone().unwrap());

                let mut malicious_parties = HashSet::new();
                for ((i, message_index), (proof, party)) in state.clone().failed_messages_indices.unwrap().into_iter().enumerate().zip(proof_results.into_iter()) {

                    let (partial_signature_decryption_share, masked_nonce_decryption_share) = state.decryption_shares[&state.party_id][message_index].clone();

                    let a : HashMap::<PartyID, _> =
                        state.proofs.clone().unwrap().into_iter().map(|(party_id, proofs)| {
                        (party_id, proofs[i].clone())
                    }).collect();

                    // TODO: make sure the proof is valid
                    identify_malicious_parties(
                        party,
                        HashMap::from([(state.party_id, partial_signature_decryption_share)]),
                        HashMap::from([(state.party_id, masked_nonce_decryption_share)]),
                        state.tiresias_public_parameters.clone(),
                        a,
                    ).iter().for_each(|party_id| {
                        malicious_parties.insert(*party_id);
                    });
                }
                println!("malicious parties: {:?}", malicious_parties);
                Ok(SignRoundCompletion::MaliciousPartiesOutput(malicious_parties))
            }
            _ => {
                Ok(SignRoundCompletion::None)
            }
        }
    }
}


pub(crate) enum SignRoundCompletion {
    SignatureOutput(Vec<Vec<u8>>),
    ProofsMessage(),
    MaliciousPartiesOutput(HashSet<PartyID>),
    None,
}

#[derive(Clone)]
pub(crate) struct SignState {
    epoch: EpochId,
    pub party_id: PartyID,
    parties: HashSet<PartyID>,
    aggregator_party_id: PartyID,
    tiresias_public_parameters: DecryptionPublicParameters,
    tiresias_key_share_decryption_key_share: SecretKeyShareSizedNumber,
    messages: Option<Vec<Vec<u8>>>,
    public_nonce_encrypted_partial_signature_and_proofs: Option<Vec<PublicNonceEncryptedPartialSignatureAndProof<ProtocolContext>>>,
    presigns: Option<Vec<DecentralizedPartyPresign>>,
    decryption_shares: HashMap<PartyID, Vec<(PaillierModulusSizedNumber, PaillierModulusSizedNumber)>>,
    pub proofs: Option<HashMap<PartyID, Vec<(PartialDecryptionProof)>>>,
    failed_messages_indices: Option<Vec<usize>>,
}

impl SignState {
    pub(crate) fn new(
        tiresias_key_share_decryption_key_share: SecretKeyShareSizedNumber,
        tiresias_public_parameters: DecryptionPublicParameters,
        epoch: EpochId,
        party_id: PartyID,
        parties: HashSet<PartyID>,
        session_id: SignatureMPCSessionID,
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
            presigns: None,
            proofs: None,
            failed_messages_indices: None,
        }
    }

    pub(crate) fn set(
        &mut self,
        messages: Vec<Vec<u8>>,
        public_nonce_encrypted_partial_signature_and_proofs: Vec<PublicNonceEncryptedPartialSignatureAndProof<ProtocolContext>>,
        presigns: Vec<DecentralizedPartyPresign>,
    ) {
        self.messages = Some(messages);
        self.public_nonce_encrypted_partial_signature_and_proofs = Some(public_nonce_encrypted_partial_signature_and_proofs);
        self.presigns = Some(presigns);
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
