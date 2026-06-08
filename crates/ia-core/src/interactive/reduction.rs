//! Interactive oracle reduction prover and verifier roles.

use crate::VerificationResult;
use crate::channel::{ProverChannel, VerifierChannel};
use crate::{ReductionCore, ReductionProverCore};

/// Prover half of an executable public-coin interactive oracle reduction.
pub trait InteractiveReductionProver: ReductionProverCore {
    /// Prover logic: takes `(source_instance, source_witness)` and returns both the target
    /// instance and target witness.  In a public-coin protocol the prover can always compute
    /// the target instance (it sees the same transcript as the verifier).
    fn prove<P: ProverChannel<Unit = u8>>(
        &self,
        ch: &mut P,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (Self::TargetInstance, Self::TargetWitness);
}

/// Verifier half of an executable public-coin interactive oracle reduction.
pub trait InteractiveReductionVerifier: ReductionCore {
    /// Verifier logic: returns a new instance, not accept/reject.
    fn verify<V: VerifierChannel<Unit = u8>>(
        &self,
        ch: &mut V,
        instance: &Self::SourceInstance,
    ) -> VerificationResult<Self::TargetInstance>;
}
