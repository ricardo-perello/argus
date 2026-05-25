//! Interactive oracle reduction trait (`InteractiveReduction`).

use crate::VerificationResult;
use crate::channel::{ProverChannel, VerifierChannel};
use crate::protocol::ReductionBody;

/// Executable public-coin interactive oracle reduction.
///
/// Unlike an `InteractiveArgument` whose verifier outputs accept/reject,
/// an `InteractiveReduction` verifier outputs a **new instance** of a
/// (potentially simpler) target relation.  The prover consumes a
/// *source* witness and produces a *target* witness for the reduced claim.
pub trait InteractiveReduction: ReductionBody {
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
