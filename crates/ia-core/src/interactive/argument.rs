//! Interactive argument traits: the prover half ([`InteractiveArgumentProver`]),
//! the verifier half ([`InteractiveArgumentVerifier`]), and their conjunction
//! ([`InteractiveArgument`]).

use crate::ArgumentCore;
use crate::VerificationResult;
use crate::channel::{ProverChannel, VerifierChannel};

/// Prover half of an executable public-coin interactive argument.
pub trait InteractiveArgumentProver: ArgumentCore {
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

/// Executable public-coin interactive argument: both prover and verifier halves.
///
/// This is a marker conjunction of [`InteractiveArgumentProver`] and
/// [`InteractiveArgumentVerifier`]; the blanket impl makes any type implementing
/// both halves an `InteractiveArgument` automatically. Authors implement the two
/// halves (directly or via `impl_interactive_argument!`), never this trait. A
/// backend that only proves can bound on the prover half alone, and one that only
/// verifies on the verifier half.
pub trait InteractiveArgument: InteractiveArgumentProver + InteractiveArgumentVerifier {}

impl<T: InteractiveArgumentProver + InteractiveArgumentVerifier> InteractiveArgument for T {}
