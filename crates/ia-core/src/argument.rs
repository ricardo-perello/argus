//! Interactive argument trait (`InteractiveArgument`).

use crate::VerificationResult;
use crate::channel::{ProverChannel, VerifierChannel};
use crate::protocol::ArgumentCore;

/// Executable public-coin interactive argument.
pub trait InteractiveArgument: ArgumentCore {
    /// Prover logic: writes messages to and reads challenges from a `ProverChannel`.
    fn prove<P: ProverChannel>(
        &self,
        ch: &mut P,
        instance: &Self::Instance,
        witness: &Self::Witness,
    );

    /// Verifier logic: reads messages from and derives challenges from a `VerifierChannel`.
    fn verify<V: VerifierChannel>(
        &self,
        ch: &mut V,
        instance: &Self::Instance,
    ) -> VerificationResult<()>;
}
