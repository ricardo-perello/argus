//! Preprocessed non-interactive protocols (keys-as-inputs).
//!
//! A [`PreprocessingNonInteractiveArgument`] is the compiled, *stateless* result
//! of running a preprocessing interactive argument through a backend such as DSFS.
//! Unlike a plain [`crate::NonInteractiveArgument`], it has an indexer
//! ([`preprocess`](PreprocessingNonInteractiveArgument::preprocess)) that derives a
//! [`ProvingKey`] and a verifier key, and `prove`/`verify` take the relevant key as
//! an input. The compiled object stores no keys, so a value built to verify carries
//! no prover material.

use crate::{
    ArgumentCore, NargProof, PreprocessingCore, ProvingKey, ReductionCore, VerificationResult,
};

/// Non-interactive argument produced from a preprocessed body.
///
/// `preprocess` is the indexer: it wraps the body's [`PreprocessingCore::index`]
/// into a [`ProvingKey`] (with the committed index baked in) plus a verifier key.
/// `prove` takes the proving key; `verify` takes the verifier key and derives the
/// committed index from it (`vk.committed_index()`). Keys are inputs, never stored.
pub trait PreprocessingNonInteractiveArgument: ArgumentCore + PreprocessingCore {
    /// Public session/context data bound into the non-interactive proof.
    type Session;

    /// Indexer: derive `(proving_key, verifier_key)` from the index.
    ///
    /// Named `preprocess` to avoid colliding with [`PreprocessingCore::index`],
    /// which returns the bare `(ProverKey, VerifierKey)`. `preprocess` additionally
    /// bakes `vk.committed_index()` into the [`ProvingKey`].
    fn preprocess(&self, ix: &Self::Index) -> (ProvingKey<Self::ProverKey>, Self::VerifierKey);

    /// Produce a non-interactive proof using the proving key.
    fn prove(
        &self,
        proving_key: &ProvingKey<Self::ProverKey>,
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
/// Reduction counterpart to [`PreprocessingNonInteractiveArgument`]: same indexer
/// + keys-as-inputs shape, with the standard reduction signatures.
pub trait PreprocessingNonInteractiveReduction: ReductionCore + PreprocessingCore {
    /// Public session/context data bound into the non-interactive proof.
    type Session;

    /// Indexer: derive `(proving_key, verifier_key)` from the index.
    fn preprocess(&self, ix: &Self::Index) -> (ProvingKey<Self::ProverKey>, Self::VerifierKey);

    /// Produce a proof and the reduced target using the proving key.
    fn prove(
        &self,
        proving_key: &ProvingKey<Self::ProverKey>,
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
