//! Non-interactive reduction abstraction.

use crate::{NargProof, VerificationResult};

/// Abstract non-interactive reduction.
///
/// A non-interactive reduction proves that a source instance reduces to a target
/// instance. Verification returns the target instance instead of a boolean
/// accept/reject result, mirroring [`crate::InteractiveReduction`].
///
/// Proving returns the proof plus the target instance/witness pair so callers can
/// continue a reduction pipeline without replaying the verifier.
pub trait NonInteractiveReduction {
    /// Public session or context data bound into the non-interactive proof.
    type Session;
    /// Public source statement before reduction.
    type SourceInstance;
    /// Public target statement produced by the reduction.
    type TargetInstance;
    /// Private witness for the source statement.
    type SourceWitness;
    /// Private witness for the target statement produced by the prover.
    type TargetWitness;

    /// Protocol identifier for the non-interactive reduction.
    fn protocol_id(&self) -> impl AsRef<[u8]>;

    /// Produce a reduction proof and the reduced target statement/witness pair.
    fn prove(
        &self,
        session: &Self::Session,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (NargProof, Self::TargetInstance, Self::TargetWitness);

    /// Verify a reduction proof and return the reduced target statement.
    fn verify(
        &self,
        session: &Self::Session,
        instance: &Self::SourceInstance,
        proof: &NargProof,
    ) -> VerificationResult<Self::TargetInstance>;
}
