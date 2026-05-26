//! Non-interactive argument abstraction.

use crate::{NargProof, VerificationResult};

/// Abstract non-interactive argument.
///
/// A `NonInteractiveArgument` verifies membership of an `Instance` using a
/// [`NargProof`], with optional session data bound into the compiled transcript.
/// Unlike [`crate::InteractiveArgument`], there is no channel: the prover
/// returns a proof artifact and the verifier checks that artifact.
pub trait NonInteractiveArgument {
    /// Public session or context data bound into the non-interactive proof.
    type Session;
    /// Public statement being proved.
    type Instance;
    /// Private witness used by the prover.
    type Witness;

    /// Protocol identifier for the non-interactive argument.
    ///
    /// For compilers, this should identify the compiled proof system, not only
    /// the underlying interactive protocol. If the proof layout, sponge choice,
    /// salt policy, or transcript derivation changes, the compiler-level domain
    /// separation must change as well.
    fn protocol_id(&self) -> impl AsRef<[u8]>;

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
