//! Non-interactive argument abstraction.

use crate::{ArgumentCore, NargProof, VerificationResult};

/// Abstract non-interactive argument.
///
/// A `NonInteractiveArgument` verifies membership of an `Instance` using a
/// [`NargProof`], with optional session data bound into the compiled transcript.
/// Its protocol id, instance type, and witness type come from [`ArgumentCore`].
/// Unlike [`crate::InteractiveArgument`], there is no channel: the prover
/// returns a proof artifact and the verifier checks that artifact.
pub trait NonInteractiveArgument: ArgumentCore {
    /// Public session or context data bound into the non-interactive proof.
    type Session;

    /// Produce a non-interactive proof for `instance` using `witness`.
    fn prove(
        &self,
        session: &Self::Session,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> NargProof;

    /// Verify a non-interactive proof for `instance`.
    fn verify(
        &self,
        session: &Self::Session,
        instance: &Self::Instance,
        proof: &NargProof,
    ) -> VerificationResult<()>;
}
