//! Non-interactive reduction prover and verifier roles.

use crate::{
    NargProof, NonInteractiveSession, ReductionCore, ReductionProverCore, VerificationResult,
};

/// Prover half of an abstract non-interactive reduction.
///
/// Proving returns the proof plus the reduced target instance/witness pair so
/// callers can continue a reduction pipeline without replaying the verifier.
pub trait NonInteractiveReductionProver: ReductionProverCore + NonInteractiveSession {
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
