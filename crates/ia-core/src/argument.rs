//! Interactive argument trait (`InteractiveArgument`).

use crate::channel::{ProverChannel, VerifierChannel};
use crate::error::VerificationResult;

/// Metadata and logic for a public-coin interactive argument.
pub trait InteractiveArgument {
    /// Public statement.
    type Instance;
    /// Prover's private input.
    type Witness;

    /// Unique 32-byte protocol identifier for domain separation.
    ///
    /// The full 64-byte DSFS domain separator is `protocol_id() || sponge_tag`,
    /// where the sponge tag is appended by the DSFS backend.  This lets the label
    /// remain human-readable while encoding the hash-function choice at the DSFS level.
    fn protocol_id() -> [u8; 32];

    /// Prover logic: writes messages to and reads challenges from a `ProverChannel`.
    fn prove<P: ProverChannel>(ch: &mut P, instance: &Self::Instance, witness: &Self::Witness);

    /// Verifier logic: reads messages from and derives challenges from a `VerifierChannel`.
    fn verify<V: VerifierChannel>(ch: &mut V, instance: &Self::Instance) -> VerificationResult<()>;
}
