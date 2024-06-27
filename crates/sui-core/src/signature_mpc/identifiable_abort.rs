use crate::authority::authority_per_epoch_store::AuthorityPerEpochStore;
use crate::signature_mpc::sign_round::{SignRound, SignRoundCompletion};
use crate::signature_mpc::sign_state::SignState;
use crate::signature_mpc::submit_to_consensus::SubmitSignatureMPC;
use dashmap::DashMap;
use mysten_metrics::spawn_monitored_task;
use signature::rand_core::CryptoRngCore;
use signature_mpc::decrypt::PartialDecryptionProof;
use signature_mpc::twopc_mpc_protocols;
use signature_mpc::twopc_mpc_protocols::{
    identify_malicious_parties, signature_partial_decryption_verification_round,
    AdditivelyHomomorphicDecryptionKeyShare, DecryptionKeyShare, PaillierModulusSizedNumber, PartyID,
    ProofParty,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use sui_types::base_types::{EpochId, ObjectRef};
use sui_types::messages_signature_mpc::{
    SignatureMPCMessageProtocols, SignatureMPCMessageSummary, SignatureMPCSessionID,
};

pub fn generate_proofs(
    state: &SignState,
    failed_messages_indices: &Vec<usize>,
) -> Vec<(PartialDecryptionProof, ProofParty)> {
    let decryption_key_share = DecryptionKeyShare::new(
        state.party_id,
        state.tiresias_key_share_decryption_key_share,
        &state.tiresias_public_parameters,
    )
    .unwrap();

    failed_messages_indices
        .iter()
        .map(|index| {
            generate_proof(
                state.tiresias_public_parameters.clone(),
                decryption_key_share.clone(),
                state.party_id,
                state.presigns.clone().unwrap().get(*index).unwrap().clone(),
                state
                    .tiresias_public_parameters
                    .encryption_scheme_public_parameters
                    .clone(),
                state
                    .public_nonce_encrypted_partial_signature_and_proofs
                    .clone()
                    .unwrap()
                    .get(*index)
                    .unwrap()
                    .clone(),
            )
        })
        .collect()
}

pub(crate) fn identify_malicious(state: &SignState) -> twopc_mpc_protocols::Result<SignRoundCompletion> {
    let proof_results = generate_proofs(&state, &state.failed_messages_indices.clone().unwrap());
    let mut malicious_parties = HashSet::new();
    let involved_shares = get_involved_shares(&state);
    for ((i, message_index), (_, party)) in state
        .clone()
        .failed_messages_indices
        .unwrap()
        .into_iter()
        .enumerate()
        .zip(proof_results.into_iter())
    {
        let shares = extract_shares(&involved_shares, message_index, 0);
        let masked_shares = extract_shares(&involved_shares, message_index, 1);
        let involved_proofs = get_involved_proofs(&state, i);
        identify_malicious_parties(
            party,
            shares,
            masked_shares,
            state.tiresias_public_parameters.clone(),
            involved_proofs,
            state.involved_parties.clone(),
        )
        .iter()
        .for_each(|party_id| {
            malicious_parties.insert(*party_id);
        });
    }
    Ok(SignRoundCompletion::MaliciousPartiesOutput(malicious_parties))
}

fn extract_shares(
    involved_shares: &HashMap<PartyID, Vec<(PaillierModulusSizedNumber, PaillierModulusSizedNumber)>>,
    message_index: usize,
    element_index: usize,
) -> HashMap<PartyID, PaillierModulusSizedNumber> {
    involved_shares
        .iter()
        .map(|(party_id, shares)| {
            let element = match element_index {
                0 => shares[message_index].0.clone(),
                1 => shares[message_index].1.clone(),
                _ => panic!("Invalid element index"),
            };
            (*party_id, element)
        })
        .collect()
}

fn get_involved_shares(
    state: &SignState,
) -> HashMap<PartyID, Vec<(PaillierModulusSizedNumber, PaillierModulusSizedNumber)>> {
    state
        .clone()
        .decryption_shares
        .into_iter()
        .filter(|(party_id, _)| state.involved_parties.contains(party_id))
        .collect()
}

fn get_involved_proofs(state: &SignState, i: usize) -> HashMap<PartyID, PartialDecryptionProof> {
    state
        .proofs
        .clone()
        .unwrap()
        .into_iter()
        .map(|(party_id, proofs)| (party_id, proofs[i].clone()))
        .collect()
}

pub fn spawn_generate_proof(
    epoch: EpochId,
    epoch_store: Arc<AuthorityPerEpochStore>,
    party_id: PartyID,
    session_id: SignatureMPCSessionID,
    session_ref: ObjectRef,
    sign_session_rounds: Arc<DashMap<SignatureMPCSessionID, SignRound>>,
    sign_session_states: Arc<DashMap<SignatureMPCSessionID, SignState>>,
    submit: Arc<dyn SubmitSignatureMPC>,
    failed_messages_indices: Vec<usize>,
    involved_parties: Vec<PartyID>,
) {
    spawn_monitored_task!(async move {
        let mut mut_state = sign_session_states.get_mut(&session_id).unwrap();
        let state = mut_state.clone();
        let proofs = generate_proofs(&state, &failed_messages_indices);
        let proofs: Vec<_> = proofs.iter().map(|(proof, _)| proof.clone()).collect();
        mut_state.insert_proofs(party_id, proofs.clone());
        let _ = submit
            .sign_and_submit_message(
                &SignatureMPCMessageSummary::new(
                    epoch,
                    SignatureMPCMessageProtocols::SignProofs(
                        state.party_id,
                        proofs.clone(),
                        failed_messages_indices.clone(),
                        involved_parties,
                    ),
                    session_id,
                ),
                &epoch_store,
            )
            .await;

        // TODO: Handle error properly
        if state.should_identify_malicious_actors() {
            if let Ok(SignRoundCompletion::MaliciousPartiesOutput(malicious_parties)) =
                identify_malicious(&state)
            {
                println!("Identified malicious parties: {:?}", malicious_parties);
            }
        }
    });
}


// write a test for the generate proofs function
// #[cfg(test)]
// mod tests {
//     use super::*;
//     use signature_mpc::twopc_mpc_protocols::PaillierModulusSizedNumber;
//     use signature_mpc::decrypt::PartialDecryptionProof;
//
//     #[test]
//     fn test_generate_proofs() {
//         // Setup dummy data
//         let state = SignState::new();
//
//         let failed_messages_indices = vec![0];
//
//         // Call the function
//         let proofs = generate_proofs(&state, &failed_messages_indices);
//
//         // Validate the result
//         assert!(!proofs.is_empty());
//     }
// }
