//! Preprocessed non-interactive protocols (keys-as-inputs).
//!
//! These are the compiled, stateless prover and verifier roles produced from
//! preprocessing interactive protocols. Each executable role receives only its
//! own key; an independent [`crate::Indexer`] derives the key pair.

use crate::{
    ArgumentCore, ArgumentProverCore, CommittedIndex, NargProof, NonInteractiveSession,
    ReductionCore, ReductionProverCore, VerificationResult,
};

/// Prover half of a non-interactive argument produced from a preprocessed body.
///
/// Keys are inputs: `prove` takes the prover key. The compiled object derives the
/// committed index on the fly from the key — `prover_key.committed_index()` (see
/// [`crate::CommittedIndex`]). Callers obtain the key from
/// [`crate::Indexer::preprocess`] and pass it in directly.
pub trait PreprocessingNonInteractiveArgumentProver:
    ArgumentProverCore + NonInteractiveSession
{
    type ProverKey: CommittedIndex;

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
    ArgumentCore + NonInteractiveSession
{
    type VerifierKey: CommittedIndex;

    /// Verify a non-interactive proof using the verifier key.
    fn verify(
        &self,
        verifier_key: &Self::VerifierKey,
        session: &Self::Session,
        instance: &Self::Instance,
        proof: &NargProof,
    ) -> VerificationResult<()>;
}

/// Prover half of a non-interactive reduction produced from a preprocessed body.
///
/// Reduction counterpart to [`PreprocessingNonInteractiveArgumentProver`]: same
/// keys-as-inputs shape, with the standard reduction signature.
pub trait PreprocessingNonInteractiveReductionProver:
    ReductionProverCore + NonInteractiveSession
{
    type ProverKey: CommittedIndex;

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
    ReductionCore + NonInteractiveSession
{
    type VerifierKey: CommittedIndex;

    /// Verify a proof and recompute the reduced target instance using the verifier key.
    fn verify(
        &self,
        verifier_key: &Self::VerifierKey,
        session: &Self::Session,
        instance: &Self::SourceInstance,
        proof: &NargProof,
    ) -> VerificationResult<Self::TargetInstance>;
}
