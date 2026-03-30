//! Non-interactive Σ proofs via the DSFS IA pipeline.
//!
//! Sigma protocols are driven through `ia-core`'s [`ProverChannel`] / [`VerifierChannel`] traits,
//! so commitments and responses go through `send_prover_message` (absorb + append to NARG).
//! The proof is the full spongefish NARG string.
//!
//! This matches `sigma-proofs::Nizk::prove_batchable` (PR #130+), where both commitments and
//! responses are recorded via `prover_messages` and the proof is the complete NARG string.

use alloc::vec::Vec;
use core::any::TypeId;

use dsfs::{ByteDuplexSponge, Keccak, SpongeProver, SpongeVerifier};
use ia_core::{ProverChannel, VerifierChannel};
use sigma_proofs::{
    errors::Error,
    traits::{ScalarRng, SigmaProtocol},
};
use spongefish::protocol_id as spongefish_protocol_id;

use crate::session::derive_session_id;

/// 64-byte domain tag absorbed inside the Keccak transcript’s first full-rate block.
///
/// `CanonicalLinearRelation` uses the Shake128 σ-proofs label for [`SigmaProtocol::protocol_identifier`],
/// while `sigma/OWKeccak1600+Bls12381` vectors carry the Keccak ciphersuite string in that slot.
fn transcript_protocol_id<P, H>(protocol: &P) -> [u8; 64]
where
    P: SigmaProtocol,
    H: ByteDuplexSponge + dsfs::TranscriptSponge + 'static,
{
    let id = protocol.protocol_identifier();
    if TypeId::of::<H>() == TypeId::of::<Keccak>() {
        let bls_shake =
            spongefish_protocol_id(core::format_args!("sigma-proofs_Shake128_BLS12381"));
        if id == bls_shake {
            return spongefish_protocol_id(core::format_args!("sigma/OWKeccak1600+Bls12381"));
        }
    }
    id
}

/// Prove a sigma protocol through the DSFS IA pipeline.
///
/// Each commitment and response element is sent via [`ProverChannel::send_prover_message`]
/// (absorb into sponge **and** append to the NARG string). The returned proof bytes are
/// the complete NARG string.
pub fn prove<P, H>(
    sponge: H,
    session_id: &[u8],
    protocol: &P,
    witness: &P::Witness,
    rng: &mut impl ScalarRng,
) -> Result<Vec<u8>, Error>
where
    P: SigmaProtocol,
    P::Challenge: PartialEq,
    H: ByteDuplexSponge + dsfs::TranscriptSponge + 'static,
{
    let instance_label = protocol.instance_label().as_ref().to_vec();
    let session = derive_session_id(session_id);
    let protocol_id = transcript_protocol_id::<P, H>(protocol);
    let mut ch = SpongeProver::new(sponge.prover_state(protocol_id, session, &instance_label));

    let (commitment, ip_state) = protocol.prover_commit(witness, rng)?;
    for c in &commitment {
        ch.send_prover_message(c);
    }

    let challenge: P::Challenge = ch.read_verifier_message();
    let response = protocol.prover_response(ip_state, &challenge)?;
    for r in &response {
        ch.send_prover_message(r);
    }

    Ok(ch.narg_string().to_vec())
}

/// Like [`prove`], but the 64-byte spongefish domain tag is `protocol_domain` (e.g. the spec JSON
/// `ciphersuite` field) instead of [`transcript_protocol_id`].
///
/// Use this for spec test vectors where the Fiat–Shamir protocol id in the transcript is **not**
/// [`SigmaProtocol::protocol_identifier`] (common for cross-ciphersuite JSON that still uses
/// `std_prover` / SHAKE128).
pub fn prove_with_protocol_domain<P, H>(
    sponge: H,
    session_id: &[u8],
    protocol_domain: [u8; 64],
    protocol: &P,
    witness: &P::Witness,
    rng: &mut impl ScalarRng,
) -> Result<Vec<u8>, Error>
where
    P: SigmaProtocol,
    P::Challenge: PartialEq,
    H: ByteDuplexSponge + dsfs::TranscriptSponge + 'static,
{
    let instance_label = protocol.instance_label().as_ref().to_vec();
    let session = derive_session_id(session_id);
    let mut ch = SpongeProver::new(sponge.prover_state(protocol_domain, session, &instance_label));

    let (commitment, ip_state) = protocol.prover_commit(witness, rng)?;
    for c in &commitment {
        ch.send_prover_message(c);
    }

    let challenge: P::Challenge = ch.read_verifier_message();
    let response = protocol.prover_response(ip_state, &challenge)?;
    for r in &response {
        ch.send_prover_message(r);
    }

    Ok(ch.narg_string().to_vec())
}

/// Verify a proof produced by [`prove_with_protocol_domain`].
pub fn verify_with_protocol_domain<P, H>(
    sponge: H,
    session_id: &[u8],
    protocol_domain: [u8; 64],
    protocol: &P,
    proof: &[u8],
) -> Result<(), Error>
where
    P: SigmaProtocol,
    P::Challenge: PartialEq,
    H: ByteDuplexSponge + dsfs::TranscriptSponge + 'static,
{
    let instance_label = protocol.instance_label().as_ref().to_vec();
    let session = derive_session_id(session_id);
    let mut ch = SpongeVerifier::new(sponge.verifier_state(
        protocol_domain,
        session,
        &instance_label,
        proof,
    ));

    let mut commitment = Vec::with_capacity(protocol.commitment_len());
    for _ in 0..protocol.commitment_len() {
        commitment.push(
            ch.read_prover_message::<P::Commitment>()
                .map_err(|_| Error::VerificationFailure)?,
        );
    }

    let challenge: P::Challenge = ch.send_verifier_message();

    let mut response = Vec::with_capacity(protocol.response_len());
    for _ in 0..protocol.response_len() {
        response.push(
            ch.read_prover_message::<P::Response>()
                .map_err(|_| Error::VerificationFailure)?,
        );
    }

    ch.state
        .check_eof()
        .map_err(|_| Error::VerificationFailure)?;

    protocol.verifier(&commitment, &challenge, &response)
}

/// Verify a sigma proof produced by [`prove`].
///
/// The proof is the full NARG string: commitment(s) then response(s), read back via
/// [`VerifierChannel::read_prover_message`].
pub fn verify<P, H>(
    sponge: H,
    session_id: &[u8],
    protocol: &P,
    proof: &[u8],
) -> Result<(), Error>
where
    P: SigmaProtocol,
    P::Challenge: PartialEq,
    H: ByteDuplexSponge + dsfs::TranscriptSponge + 'static,
{
    let instance_label = protocol.instance_label().as_ref().to_vec();
    let session = derive_session_id(session_id);
    let protocol_id = transcript_protocol_id::<P, H>(protocol);
    let mut ch = SpongeVerifier::new(sponge.verifier_state(
        protocol_id,
        session,
        &instance_label,
        proof,
    ));

    let mut commitment = Vec::with_capacity(protocol.commitment_len());
    for _ in 0..protocol.commitment_len() {
        commitment.push(
            ch.read_prover_message::<P::Commitment>()
                .map_err(|_| Error::VerificationFailure)?,
        );
    }

    let challenge: P::Challenge = ch.send_verifier_message();

    let mut response = Vec::with_capacity(protocol.response_len());
    for _ in 0..protocol.response_len() {
        response.push(
            ch.read_prover_message::<P::Response>()
                .map_err(|_| Error::VerificationFailure)?,
        );
    }

    ch.state
        .check_eof()
        .map_err(|_| Error::VerificationFailure)?;

    protocol.verifier(&commitment, &challenge, &response)
}
