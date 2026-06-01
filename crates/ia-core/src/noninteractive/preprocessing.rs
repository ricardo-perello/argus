//! Preprocessed non-interactive protocols (keys-as-inputs).
//!
//! A [`PreprocessingNonInteractiveArgument`] is the compiled, *stateless* result
//! of running a preprocessing interactive argument through a backend such as DSFS.
//! Unlike a plain [`crate::NonInteractiveArgument`], `prove`/`verify` take the
//! relevant preprocessed key as an input. The preprocessing step
//! ([`PreprocessingCore::preprocess`]) derives `(prover_key, verifier_key)`;
//! the compiled object stores no keys, so a value built to verify carries no
//! prover material.

use crate::{ArgumentCore, NargProof, PreprocessingCore, ReductionCore, VerificationResult};

/// Non-interactive argument produced from a preprocessed body.
///
/// Keys are inputs: `prove` takes the prover key, `verify` takes the verifier key.
/// The compiled object derives the committed index on the fly from whichever key it
/// is handed — `prover_key.committed_index()` on the prover side and
/// `verifier_key.committed_index()` on the verifier side (see [`crate::CommittedIndex`]).
/// There is no separate indexer method and no precomputed-digest wrapper; callers
/// obtain the keys from [`PreprocessingCore::preprocess`] and pass them in directly.
pub trait PreprocessingNonInteractiveArgument: ArgumentCore + PreprocessingCore {
    /// Public session/context data bound into the non-interactive proof.
    type Session;

    /// Produce a non-interactive proof using the prover key.
    ///
    /// Binds `prover_key.committed_index()` into the transcript before the first
    /// challenge.
    fn prove(
        &self,
        prover_key: &Self::ProverKey,
        session: &Self::Session,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> NargProof;

    /// Verify a non-interactive proof using the verifier key.
    fn verify(
        &self,
        verifier_key: &Self::VerifierKey,
        session: &Self::Session,
        instance: &Self::Instance,
        proof: &NargProof,
    ) -> VerificationResult<()>;
}

/// Non-interactive reduction produced from a preprocessed body.
///
/// Reduction counterpart to [`PreprocessingNonInteractiveArgument`]: same
/// keys-as-inputs shape, with the standard reduction signatures.
pub trait PreprocessingNonInteractiveReduction: ReductionCore + PreprocessingCore {
    /// Public session/context data bound into the non-interactive proof.
    type Session;

    /// Produce a proof and the reduced target using the prover key.
    ///
    /// Binds `prover_key.committed_index()` into the transcript before the first
    /// challenge.
    fn prove(
        &self,
        prover_key: &Self::ProverKey,
        session: &Self::Session,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (NargProof, Self::TargetInstance, Self::TargetWitness);

    /// Verify a proof and recompute the reduced target instance using the verifier key.
    fn verify(
        &self,
        verifier_key: &Self::VerifierKey,
        session: &Self::Session,
        instance: &Self::SourceInstance,
        proof: &NargProof,
    ) -> VerificationResult<Self::TargetInstance>;
}
