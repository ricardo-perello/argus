//! Preprocessed non-interactive protocols (keys-as-inputs).
//!
//! A [`PreprocessingNonInteractiveArgument`] is the compiled, *stateless* result
//! of running a preprocessing interactive argument through a backend such as DSFS.
//! Unlike a plain [`crate::NonInteractiveArgument`], `prove`/`verify` take the
//! relevant preprocessed key as an input. The preprocessing step
//! ([`PreprocessingCore::preprocess`]) derives `(prover_key, verifier_key)`;
//! the compiled object stores no keys, so a value built to verify carries no
//! prover material.

use crate::{
    ArgumentCore, NargProof, NonInteractiveSession, PreprocessingCore, ReductionCore,
    VerificationResult,
};

/// Prover half of a non-interactive argument produced from a preprocessed body.
///
/// Keys are inputs: `prove` takes the prover key. The compiled object derives the
/// committed index on the fly from the key — `prover_key.committed_index()` (see
/// [`crate::CommittedIndex`]). Callers obtain the key from
/// [`PreprocessingCore::preprocess`] and pass it in directly.
pub trait PreprocessingNonInteractiveArgumentProver:
    ArgumentCore + PreprocessingCore + NonInteractiveSession
{
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
}

/// Verifier half of a non-interactive argument produced from a preprocessed body.
pub trait PreprocessingNonInteractiveArgumentVerifier:
    ArgumentCore + PreprocessingCore + NonInteractiveSession
{
    /// Verify a non-interactive proof using the verifier key.
    fn verify(
        &self,
        verifier_key: &Self::VerifierKey,
        session: &Self::Session,
        instance: &Self::Instance,
        proof: &NargProof,
    ) -> VerificationResult<()>;
}

/// Non-interactive argument produced from a preprocessed body: both halves.
/// Marker conjunction of [`PreprocessingNonInteractiveArgumentProver`] and
/// [`PreprocessingNonInteractiveArgumentVerifier`].
pub trait PreprocessingNonInteractiveArgument:
    PreprocessingNonInteractiveArgumentProver + PreprocessingNonInteractiveArgumentVerifier
{
}

impl<T> PreprocessingNonInteractiveArgument for T where
    T: PreprocessingNonInteractiveArgumentProver + PreprocessingNonInteractiveArgumentVerifier
{
}

/// Prover half of a non-interactive reduction produced from a preprocessed body.
///
/// Reduction counterpart to [`PreprocessingNonInteractiveArgumentProver`]: same
/// keys-as-inputs shape, with the standard reduction signature.
pub trait PreprocessingNonInteractiveReductionProver:
    ReductionCore + PreprocessingCore + NonInteractiveSession
{
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
}

/// Verifier half of a non-interactive reduction produced from a preprocessed body.
pub trait PreprocessingNonInteractiveReductionVerifier:
    ReductionCore + PreprocessingCore + NonInteractiveSession
{
    /// Verify a proof and recompute the reduced target instance using the verifier key.
    fn verify(
        &self,
        verifier_key: &Self::VerifierKey,
        session: &Self::Session,
        instance: &Self::SourceInstance,
        proof: &NargProof,
    ) -> VerificationResult<Self::TargetInstance>;
}

/// Non-interactive reduction produced from a preprocessed body: both halves.
/// Marker conjunction of [`PreprocessingNonInteractiveReductionProver`] and
/// [`PreprocessingNonInteractiveReductionVerifier`].
pub trait PreprocessingNonInteractiveReduction:
    PreprocessingNonInteractiveReductionProver + PreprocessingNonInteractiveReductionVerifier
{
}

impl<T> PreprocessingNonInteractiveReduction for T where
    T: PreprocessingNonInteractiveReductionProver + PreprocessingNonInteractiveReductionVerifier
{
}
