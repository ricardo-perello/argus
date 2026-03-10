//! Core abstractions for public-coin interactive arguments and reductions.
//!
//! Defines channel traits, the `InteractiveArgument` interface, and the
//! `InteractiveReduction` interface. This crate has **zero external
//! dependencies** -- all sponge-specific bounds live on the implementation
//! side (in `dsfs`).
#![no_std]

/// Verification failed.
#[derive(Debug, Clone, Copy)]
pub struct VerificationError;

/// Result type for verification operations.
pub type VerificationResult<T> = Result<T, VerificationError>;

// ---------------------------------------------------------------------------
// Channel traits -- parameterized, zero bounds on M/C
// ---------------------------------------------------------------------------

/// Prover sends a message of type `M` into the channel.
pub trait SendProverMessage<M> {
    fn send_prover_message(&mut self, msg: &M);
}

/// Verifier reads a prover message of type `M` from the proof.
pub trait ReadProverMessage<M> {
    fn read_prover_message(&mut self) -> VerificationResult<M>;
}

/// Verifier derives a message (challenge) of type `C`.
pub trait SendVerifierMessage<C> {
    fn send_verifier_message(&mut self) -> C;
}

/// Prover receives a verifier message (challenge) of type `C`.
pub trait ReadVerifierMessage<C> {
    fn read_verifier_message(&mut self) -> C;
}

// ---------------------------------------------------------------------------
// Interactive Argument traits
// ---------------------------------------------------------------------------

/// Metadata for a public-coin interactive argument.
pub trait InteractiveArgument {
    /// Public statement.
    type Instance;
    /// Prover's private input.
    type Witness;

    /// Unique 64-byte protocol identifier for domain separation.
    fn protocol_id() -> [u8; 64];
}

/// Prover logic: writes messages to and reads challenges from channel `P`.
pub trait Prove<P>: InteractiveArgument {
    fn prove(ch: &mut P, instance: &Self::Instance, witness: &Self::Witness);
}

/// Verifier logic: reads messages from and derives challenges from channel `V`.
pub trait Verify<V>: InteractiveArgument {
    fn verify(ch: &mut V, instance: &Self::Instance) -> VerificationResult<()>;
}

// ---------------------------------------------------------------------------
// Interactive Reduction traits
// ---------------------------------------------------------------------------

/// Metadata for a public-coin interactive oracle reduction.
///
/// Unlike an `InteractiveArgument` whose verifier outputs accept/reject,
/// an `InteractiveReduction` verifier outputs a **new instance** of a
/// (potentially simpler) target relation.
pub trait InteractiveReduction {
    /// Input instance (the claim being reduced).
    type SourceInstance;
    /// Output instance (the reduced claim the verifier computes).
    type TargetInstance;
    /// Prover's private input.
    type Witness;

    /// Unique 64-byte protocol identifier for domain separation.
    fn protocol_id() -> [u8; 64];
}

/// Prover logic for an interactive reduction.
pub trait ReduceProve<P>: InteractiveReduction {
    fn prove(ch: &mut P, instance: &Self::SourceInstance, witness: &Self::Witness);
}

/// Verifier logic for an interactive reduction: returns a new instance,
/// not accept/reject.
pub trait ReduceVerify<V>: InteractiveReduction {
    fn verify(
        ch: &mut V,
        instance: &Self::SourceInstance,
    ) -> VerificationResult<Self::TargetInstance>;
}
