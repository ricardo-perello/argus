//! DSFS compiler: Duplex-Sponge Fiat-Shamir transformation (Construction 4.3, Chiesa-Orru 2025).
//!
//! Compiles a public-coin [`InteractiveArgument`] into a non-interactive argument
//! by driving the protocol round-by-round through a spongefish transcript.
//!
//! This is the only layer that touches the sponge. The IA never interacts with
//! spongefish directly.
#![no_std]
extern crate alloc;

use alloc::vec::Vec;

use ia_core::{InteractiveArgument, Round, Transcript};
use spongefish::{
    Decoding, DomainSeparator, Encoding, NargDeserialize, VerificationError, VerificationResult,
};

/// Non-interactive prover: drives the IA round-by-round through spongefish.
///
/// Follows Construction 4.3 exactly:
///   1. Initialize sponge with protocol_id, session, instance.
///   2. For each of the k rounds: absorb prover message, squeeze verifier challenge.
///   3. Return the NARG string (proof bytes).
pub fn prove<IA>(
    session: [u8; 64],
    instance: &IA::Instance,
    witness: &IA::Witness,
) -> Vec<u8>
where
    IA: InteractiveArgument,
    IA::Instance: Encoding<[u8]>,
    IA::ProverMessage: Encoding<[u8]>,
    IA::VerifierChallenge: Decoding<[u8]>,
{
    let domsep = DomainSeparator::new(IA::protocol_id())
        .session(session)
        .instance(instance);

    let mut sponge = domsep.std_prover();
    let mut state = IA::prover_init(instance, witness);
    let k = IA::num_rounds(instance);

    let mut prev_challenge: Option<IA::VerifierChallenge> = None;
    for _ in 0..k {
        let msg = IA::prover_round(&mut state, prev_challenge.as_ref());
        sponge.prover_message(&msg);
        prev_challenge = Some(sponge.verifier_message());
    }

    sponge.narg_string().to_vec()
}

/// Non-interactive verifier: replays the transcript deterministically, then
/// delegates the final accept/reject decision to the IA's verification predicate.
///
/// Follows Construction 4.3 exactly:
///   1. Initialize sponge with protocol_id, session, instance.
///   2. For each of the k rounds: deserialize + absorb prover message, squeeze challenge.
///   3. Check no trailing bytes (EOF).
///   4. Run IA::verify on the reconstructed transcript.
pub fn verify<IA>(
    session: [u8; 64],
    instance: &IA::Instance,
    proof: &[u8],
) -> VerificationResult<()>
where
    IA: InteractiveArgument,
    IA::Instance: Encoding<[u8]>,
    IA::ProverMessage: Encoding<[u8]> + NargDeserialize,
    IA::VerifierChallenge: Decoding<[u8]>,
{
    let domsep = DomainSeparator::new(IA::protocol_id())
        .session(session)
        .instance(instance);

    let mut sponge = domsep.std_verifier(proof);
    let k = IA::num_rounds(instance);

    let mut rounds = Vec::with_capacity(k);
    for _ in 0..k {
        let msg: IA::ProverMessage = sponge.prover_message()?;
        let challenge: IA::VerifierChallenge = sponge.verifier_message();
        rounds.push(Round {
            message: msg,
            challenge,
        });
    }

    sponge.check_eof()?;

    let transcript = Transcript { rounds };
    if IA::verify(instance, &transcript) {
        Ok(())
    } else {
        Err(VerificationError)
    }
}
