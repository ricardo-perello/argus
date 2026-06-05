//! Non-interactive reduction traits: the prover half
//! ([`NonInteractiveReductionProver`]), the verifier half
//! ([`NonInteractiveReductionVerifier`]), and their conjunction
//! ([`NonInteractiveReduction`]).

use crate::{NargProof, NonInteractiveSession, ReductionCore, VerificationResult};

/// Prover half of an abstract non-interactive reduction.
///
/// Proving returns the proof plus the reduced target instance/witness pair so
/// callers can continue a reduction pipeline without replaying the verifier.
pub trait NonInteractiveReductionProver: ReductionCore + NonInteractiveSession {
    /// Produce a reduction proof and the reduced target statement/witness pair.
    fn prove(
        &self,
        session: &Self::Session,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (NargProof, Self::TargetInstance, Self::TargetWitness);
}

/// Verifier half of an abstract non-interactive reduction.
pub trait NonInteractiveReductionVerifier: ReductionCore + NonInteractiveSession {
    /// Verify a reduction proof and return the reduced target statement.
    fn verify(
        &self,
        session: &Self::Session,
        instance: &Self::SourceInstance,
        proof: &NargProof,
    ) -> VerificationResult<Self::TargetInstance>;
}

/// Abstract non-interactive reduction: both halves.
///
/// A non-interactive reduction proves that a source instance reduces to a target
/// instance. Verification returns the target instance instead of accept/reject,
/// mirroring [`crate::InteractiveReduction`]. Marker conjunction of
/// [`NonInteractiveReductionProver`] and [`NonInteractiveReductionVerifier`].
pub trait NonInteractiveReduction:
    NonInteractiveReductionProver + NonInteractiveReductionVerifier
{
}

impl<T: NonInteractiveReductionProver + NonInteractiveReductionVerifier> NonInteractiveReduction
    for T
{
}
