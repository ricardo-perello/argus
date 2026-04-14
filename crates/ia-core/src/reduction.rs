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

    /// Variable-length protocol identifier for domain separation.
    ///
    /// May depend on runtime structure. DSFS compacts and mixes this with a sponge
    /// tag and session to form the full domain separator.
    fn protocol_id(&self) -> impl AsRef<[u8]>;

    /// Prover logic: takes `(source_instance, source_witness)` and returns both the target
    /// instance and target witness.  In a public-coin protocol the prover can always compute
    /// the target instance (it sees the same transcript as the verifier).
    fn prove<P: ProverChannel>(
        &self,
        ch: &mut P,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (Self::TargetInstance, Self::TargetWitness);

    /// Verifier logic: returns a new instance, not accept/reject.
    fn verify<V: VerifierChannel>(
        &self,
        ch: &mut V,
        instance: &Self::SourceInstance,
    ) -> VerificationResult<Self::TargetInstance>;
}
