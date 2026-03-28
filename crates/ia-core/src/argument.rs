//! Interactive argument traits (`InteractiveArgument`, `Prove`, `Verify`).

use crate::channel::{ProverChannel, VerifierChannel};
use crate::error::VerificationResult;
use crate::security::SecurityProfile;

/// Metadata for a public-coin interactive argument.
pub trait InteractiveArgument {
    /// Public statement.
    type Instance;
    /// Prover's private input.
    type Witness;

    /// Unique 64-byte protocol identifier for domain separation.
    fn protocol_id() -> [u8; 64];

    /// Security metadata for this protocol.
    fn security() -> SecurityProfile;
}

/// Prover logic: writes messages to and reads challenges from a `ProverChannel`.
pub trait Prove<P: ProverChannel>: InteractiveArgument {
    fn prove(ch: &mut P, instance: &Self::Instance, witness: &Self::Witness);
}

/// Verifier logic: reads messages from and derives challenges from a `VerifierChannel`.
pub trait Verify<V: VerifierChannel>: InteractiveArgument {
    fn verify(ch: &mut V, instance: &Self::Instance) -> VerificationResult<()>;
}
