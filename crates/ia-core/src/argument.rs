//! Interactive argument trait (`InteractiveArgument`).

use crate::channel::{ProverChannel, VerifierChannel};
use crate::VerificationResult;

/// Metadata and logic for a public-coin interactive argument.
pub trait InteractiveArgument {
    /// Public statement.
    type Instance;
    /// Prover's private input.
    type Witness;

    /// Variable-length protocol identifier for domain separation.
    ///
    /// May depend on runtime structure of the protocol instance (e.g. a composition
    /// tree). The DSFS backend compacts and mixes this with a sponge tag and session
    /// to form the full domain separator. Leaf protocols may return a fixed
    /// `[u8; 32]` (via `pad_protocol_id`) or a short byte slice.
    fn protocol_id(&self) -> impl AsRef<[u8]>;

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
