//! Interactive argument prover and verifier roles.

use crate::VerificationResult;
use crate::channel::{ProverChannel, VerifierChannel};
use crate::{ArgumentCore, ArgumentProverCore};

/// Prover half of an executable public-coin interactive argument.
pub trait InteractiveArgumentProver: ArgumentProverCore {
    /// Prover logic: writes messages to and reads challenges from a `ProverChannel`.
    fn prove<P: ProverChannel<Unit = u8>>(
        &self,
        ch: &mut P,
        instance: &Self::Instance,
        witness: &Self::Witness,
    );
}

/// Verifier half of an executable public-coin interactive argument.
pub trait InteractiveArgumentVerifier: ArgumentCore {
    /// Verifier logic: reads messages from and derives challenges from a `VerifierChannel`.
    fn verify<V: VerifierChannel<Unit = u8>>(
        &self,
        ch: &mut V,
        instance: &Self::Instance,
    ) -> VerificationResult<()>;
}
