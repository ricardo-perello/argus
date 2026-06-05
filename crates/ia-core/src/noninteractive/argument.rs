//! Non-interactive argument traits: the prover half
//! ([`NonInteractiveArgumentProver`]), the verifier half
//! ([`NonInteractiveArgumentVerifier`]), and their conjunction
//! ([`NonInteractiveArgument`]).

use crate::{ArgumentCore, NargProof, NonInteractiveSession, VerificationResult};

/// Prover half of an abstract non-interactive argument.
///
/// Produces a [`NargProof`] for an `Instance` using a `Witness`, with optional
/// session data bound into the compiled transcript. The session type comes from
/// [`NonInteractiveSession`]; instance/witness from [`ArgumentCore`].
pub trait NonInteractiveArgumentProver: ArgumentCore + NonInteractiveSession {
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

/// Abstract non-interactive argument: both prover and verifier halves.
///
/// Unlike [`crate::InteractiveArgument`] there is no channel: the prover returns a
/// proof artifact and the verifier checks it. Marker conjunction of
/// [`NonInteractiveArgumentProver`] and [`NonInteractiveArgumentVerifier`]; the
/// blanket impl makes any type implementing both halves a `NonInteractiveArgument`
/// automatically. A backend that compiles only a prover can implement just the
/// prover half.
pub trait NonInteractiveArgument:
    NonInteractiveArgumentProver + NonInteractiveArgumentVerifier
{
}

impl<T: NonInteractiveArgumentProver + NonInteractiveArgumentVerifier> NonInteractiveArgument
    for T
{
}
