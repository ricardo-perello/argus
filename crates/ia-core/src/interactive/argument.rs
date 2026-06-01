//! Interactive argument trait (`InteractiveArgument`).

use crate::ArgumentCore;
use crate::VerificationResult;
use crate::channel::{ProverChannel, VerifierChannel};

/// Executable public-coin interactive argument.
pub trait InteractiveArgument: ArgumentCore {
    /// Prover logic: writes messages to and reads challenges from a `ProverChannel`.
    fn prove<P: ProverChannel<Unit = u8>>(
        &self,
        ch: &mut P,
        instance: &Self::Instance,
        witness: &Self::Witness,
    );

    /// Verifier logic: reads messages from and derives challenges from a `VerifierChannel`.
    fn verify<V: VerifierChannel<Unit = u8>>(
        &self,
        ch: &mut V,
        instance: &Self::Instance,
    ) -> VerificationResult<()>;
}
