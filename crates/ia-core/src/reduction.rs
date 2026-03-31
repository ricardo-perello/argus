//! Interactive oracle reduction trait (`InteractiveReduction`).

use crate::channel::{ProverChannel, VerifierChannel};
use crate::error::VerificationResult;

/// Metadata and logic for a public-coin interactive oracle reduction.
///
/// Unlike an `InteractiveArgument` whose verifier outputs accept/reject,
/// an `InteractiveReduction` verifier outputs a **new instance** of a
/// (potentially simpler) target relation.  The prover consumes a
/// *source* witness and produces a *target* witness for the reduced claim.
pub trait InteractiveReduction {
    /// Input instance (the claim being reduced).
    type SourceInstance;
    /// Output instance (the reduced claim the verifier computes).
    type TargetInstance;
    /// Prover's private input for the source relation.
    type SourceWitness;
    /// Prover's output: private input for the target relation.
    type TargetWitness;

    /// Unique 32-byte protocol identifier for domain separation.
    ///
    /// The full 64-byte DSFS domain separator is `protocol_id() || sponge_tag`,
    /// where the sponge tag is appended by the DSFS backend.
    fn protocol_id() -> [u8; 32];

    /// Prover logic: takes `(source_instance, source_witness)` and returns both the target
    /// instance and target witness.  In a public-coin protocol the prover can always compute
    /// the target instance (it sees the same transcript as the verifier).
    fn prove<P: ProverChannel>(
        ch: &mut P,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (Self::TargetInstance, Self::TargetWitness);

    /// Verifier logic: returns a new instance, not accept/reject.
    fn verify<V: VerifierChannel>(
        ch: &mut V,
        instance: &Self::SourceInstance,
    ) -> VerificationResult<Self::TargetInstance>;
}
