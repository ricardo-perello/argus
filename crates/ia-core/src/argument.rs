//! Interactive argument trait (`InteractiveArgument`).

use crate::channel::{ProverChannel, VerifierChannel};
use crate::error::VerificationResult;

/// Metadata and logic for a public-coin interactive argument.
pub trait InteractiveArgument {
    /// Public statement.
    type Instance;
    /// Prover's private input.
    type Witness;

    /// Unique 64-byte protocol identifier for domain separation.
    fn protocol_id() -> [u8; 64];

    /// Prover logic: writes messages to and reads challenges from a `ProverChannel`.
    fn prove<P: ProverChannel>(ch: &mut P, instance: &Self::Instance, witness: &Self::Witness);

    /// Verifier logic: reads messages from and derives challenges from a `VerifierChannel`.
    fn verify<V: VerifierChannel>(ch: &mut V, instance: &Self::Instance) -> VerificationResult<()>;
}
