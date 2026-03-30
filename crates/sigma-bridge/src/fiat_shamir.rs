//! Non-interactive Σ proofs via the DSFS IA pipeline.
//!
//! Sigma protocols are driven through `ia-core`'s [`ProverChannel`] / [`VerifierChannel`] traits,
//! so commitments and responses go through `send_prover_message` (absorb + append to NARG).
//! The proof is the full spongefish NARG string.

use alloc::vec::Vec;

use dsfs::{ByteDuplexSponge, SpongeProver, SpongeVerifier};
use ia_core::{ProverChannel, VerifierChannel};
use sigma_proofs::{errors::Error, traits::SigmaProtocol};
use spongefish::DomainSeparator;

use crate::session::derive_session_id;

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
    rng: &mut impl sigma_proofs::traits::ScalarRng,
) -> Result<Vec<u8>, Error>
where
    P: SigmaProtocol,
    P::Challenge: PartialEq,
    H: ByteDuplexSponge,
{
    let instance_label = protocol.instance_label().as_ref().to_vec();
    let domsep = DomainSeparator::new(protocol.protocol_identifier())
        .session(derive_session_id(session_id))
        .instance(&instance_label);
    let mut ch = SpongeProver::new(domsep.to_prover(sponge));

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
    H: ByteDuplexSponge,
{
    let instance_label = protocol.instance_label().as_ref().to_vec();
    let domsep = DomainSeparator::new(protocol.protocol_identifier())
        .session(derive_session_id(session_id))
        .instance(&instance_label);
    let mut ch = SpongeVerifier::new(domsep.to_verifier(sponge, proof));

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
