//! Non-interactive reduction abstraction.

use crate::{NargProof, ReductionCore, VerificationResult};

/// Abstract non-interactive reduction.
///
/// A non-interactive reduction proves that a source instance reduces to a target
/// instance. Verification returns the target instance instead of a boolean
/// accept/reject result, mirroring [`crate::InteractiveReduction`].
/// Its protocol id and source/target shape come from [`ReductionCore`].
///
/// Proving returns the proof plus the target instance/witness pair so callers can
/// continue a reduction pipeline without replaying the verifier.
pub trait NonInteractiveReduction: ReductionCore {
    /// Public session or context data bound into the non-interactive proof.
    type Session;

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
