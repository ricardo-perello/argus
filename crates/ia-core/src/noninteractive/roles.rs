//! Optional role wrappers over a compiled preprocessing non-interactive protocol.
//!
//! These bundle a stateless [`PreprocessingNonInteractiveArgument`] (or reduction)
//! with a single party's key, so callers don't re-pass the key on every call and so
//! a value can be typed to expose only one capability. They are pure convenience
//! over `nia.prove(proving_key, …)` / `nia.verify(verifier_key, …)`; the real
//! capability boundary is key possession (no proving key ⇒ no proof).

use crate::{
    NargProof, PreprocessingNonInteractiveArgument, PreprocessingNonInteractiveReduction,
    ProvingKey, VerificationResult,
};

/// Prover view of a compiled argument: the stateless PNIA plus its proving key.
///
/// Exposes only [`prove`](Prover::prove). Constructed from `(nia, proving_key)` —
/// it never holds the verifier key.
pub struct Prover<'a, N: PreprocessingNonInteractiveArgument> {
    nia: &'a N,
    proving_key: &'a ProvingKey<N::ProverKey>,
}

impl<'a, N: PreprocessingNonInteractiveArgument> Prover<'a, N> {
    pub fn new(nia: &'a N, proving_key: &'a ProvingKey<N::ProverKey>) -> Self {
        Self { nia, proving_key }
    }

    pub fn prove(
        &self,
        session: &N::Session,
        instance: &N::Instance,
        witness: &N::Witness,
    ) -> NargProof {
        self.nia.prove(self.proving_key, session, instance, witness)
    }
}

/// Verifier view of a compiled argument: the stateless PNIA plus its verifier key.
///
/// Exposes only [`verify`](Verifier::verify). Constructed from `(nia, verifier_key)`
/// — it has no `prove` method and never holds the proving key.
pub struct Verifier<'a, N: PreprocessingNonInteractiveArgument> {
    nia: &'a N,
    verifier_key: &'a N::VerifierKey,
}

impl<'a, N: PreprocessingNonInteractiveArgument> Verifier<'a, N> {
    pub fn new(nia: &'a N, verifier_key: &'a N::VerifierKey) -> Self {
        Self { nia, verifier_key }
    }

    pub fn verify(
        &self,
        session: &N::Session,
        instance: &N::Instance,
        proof: &NargProof,
    ) -> VerificationResult<()> {
        self.nia.verify(self.verifier_key, session, instance, proof)
    }
}

/// Prover view of a compiled reduction.
pub struct ProverReduction<'a, N: PreprocessingNonInteractiveReduction> {
    nia: &'a N,
    proving_key: &'a ProvingKey<N::ProverKey>,
}

impl<'a, N: PreprocessingNonInteractiveReduction> ProverReduction<'a, N> {
    pub fn new(nia: &'a N, proving_key: &'a ProvingKey<N::ProverKey>) -> Self {
        Self { nia, proving_key }
    }

    pub fn prove(
        &self,
        session: &N::Session,
        instance: &N::SourceInstance,
        witness: &N::SourceWitness,
    ) -> (NargProof, N::TargetInstance, N::TargetWitness) {
        self.nia.prove(self.proving_key, session, instance, witness)
    }
}

/// Verifier view of a compiled reduction.
pub struct VerifierReduction<'a, N: PreprocessingNonInteractiveReduction> {
    nia: &'a N,
    verifier_key: &'a N::VerifierKey,
}

impl<'a, N: PreprocessingNonInteractiveReduction> VerifierReduction<'a, N> {
    pub fn new(nia: &'a N, verifier_key: &'a N::VerifierKey) -> Self {
        Self { nia, verifier_key }
    }

    pub fn verify(
        &self,
        session: &N::Session,
        instance: &N::SourceInstance,
        proof: &NargProof,
    ) -> VerificationResult<N::TargetInstance> {
        self.nia.verify(self.verifier_key, session, instance, proof)
    }
}
