//! Non-interactive argument prover and verifier roles.

use crate::{
    ArgumentCore, ArgumentProverCore, NargProof, NonInteractiveSession, VerificationResult,
};

/// Prover half of an abstract non-interactive argument.
///
/// Produces a [`NargProof`] for an `Instance` using a `Witness`, with optional
/// session data bound into the compiled transcript. The session type comes from
/// [`NonInteractiveSession`]; instance/witness from [`ArgumentCore`].
pub trait NonInteractiveArgumentProver: ArgumentProverCore + NonInteractiveSession {
    /// Produce a non-interactive proof for `instance` using `witness`.
    fn prove(
        &self,
        session: &Self::Session,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> NargProof;
}

/// Verifier half of an abstract non-interactive argument.
pub trait NonInteractiveArgumentVerifier: ArgumentCore + NonInteractiveSession {
    /// Verify a non-interactive proof for `instance`.
    fn verify(
        &self,
        session: &Self::Session,
        instance: &Self::Instance,
        proof: &NargProof,
    ) -> VerificationResult<()>;
}
