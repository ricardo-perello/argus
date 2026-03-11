//! Core abstractions for public-coin interactive arguments and reductions.
//!
//! Defines channel traits, the `InteractiveArgument` interface, and the
//! `InteractiveReduction` interface.
//!
//! Codec traits (`Encoding`, `Decoding`, `NargDeserialize`) are re-exported
//! from spongefish to enable method-level generics on the channel traits.
#![no_std]

/// Verification failed.
#[derive(Debug, Clone, Copy)]
pub struct VerificationError;

/// Result type for verification operations.
pub type VerificationResult<T> = Result<T, VerificationError>;

pub use spongefish::{Decoding, Encoding, NargDeserialize};

// ---------------------------------------------------------------------------
// Channel traits -- method-level generics, 2 traits instead of 4
// ---------------------------------------------------------------------------

/// Prover-side channel: send prover messages and read verifier challenges.
pub trait ProverChannel {
    fn send_prover_message<PM: Encoding>(&mut self, msg: &PM);
    fn read_verifier_message<VM: Decoding>(&mut self) -> VM;
}

/// Verifier-side channel: read prover messages and derive verifier challenges.
pub trait VerifierChannel {
    fn read_prover_message<PM: Encoding + NargDeserialize>(&mut self) -> VerificationResult<PM>;
    fn send_verifier_message<VM: Decoding>(&mut self) -> VM;
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

/// Prover logic: writes messages to and reads challenges from a `ProverChannel`.
pub trait Prove<P: ProverChannel>: InteractiveArgument {
    fn prove(ch: &mut P, instance: &Self::Instance, witness: &Self::Witness);
}

/// Verifier logic: reads messages from and derives challenges from a `VerifierChannel`.
pub trait Verify<V: VerifierChannel>: InteractiveArgument {
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
pub trait ReduceProve<P: ProverChannel>: InteractiveReduction {
    fn prove(ch: &mut P, instance: &Self::SourceInstance, witness: &Self::Witness);
}

/// Verifier logic for an interactive reduction: returns a new instance,
/// not accept/reject.
pub trait ReduceVerify<V: VerifierChannel>: InteractiveReduction {
    fn verify(
        ch: &mut V,
        instance: &Self::SourceInstance,
    ) -> VerificationResult<Self::TargetInstance>;
}
