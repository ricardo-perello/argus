#![no_std]
extern crate alloc;

use alloc::vec::Vec;

/// A single round of interaction: prover message followed by verifier challenge.
pub struct Round<M, C> {
    pub message: M,
    pub challenge: C,
}

/// Full transcript of an interactive argument (k rounds).
pub struct Transcript<M, C> {
    pub rounds: Vec<Round<M, C>>,
}

/// A public-coin interactive argument (Construction 4.3).
///
/// Describes WHAT the protocol does. DSFS handles HOW Fiat-Shamir is applied.
/// The trait is generic and carries no sponge dependency; the DSFS layer
/// adds `Encoding`/`Decoding` bounds when compiling to a non-interactive argument.
pub trait InteractiveArgument {
    /// Public statement.
    type Instance;
    /// Prover's private input.
    type Witness;
    /// Mutable prover state across rounds.
    type ProverState;
    /// A single prover message (use an enum for multi-phase protocols).
    type ProverMessage;
    /// A single verifier challenge.
    type VerifierChallenge;

    /// Unique 64-byte protocol identifier for domain separation.
    fn protocol_id() -> [u8; 64];

    /// Number of interaction rounds k, determined by the instance.
    fn num_rounds(instance: &Self::Instance) -> usize;

    /// Initialize mutable prover state from instance and witness.
    fn prover_init(
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> Self::ProverState;

    /// Produce the prover message for the current round.
    /// `challenge` is `None` for round 0, `Some(rho_{i-1})` for round i > 0.
    /// The prover state advances internally.
    fn prover_round(
        state: &mut Self::ProverState,
        challenge: Option<&Self::VerifierChallenge>,
    ) -> Self::ProverMessage;

    /// Verification predicate: V(x, a_1, rho_1, ..., a_k, rho_k) -> accept/reject.
    fn verify(
        instance: &Self::Instance,
        transcript: &Transcript<Self::ProverMessage, Self::VerifierChallenge>,
    ) -> bool;
}
