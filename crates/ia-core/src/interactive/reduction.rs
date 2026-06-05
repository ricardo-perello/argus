//! Interactive oracle reduction traits: the prover half
//! ([`InteractiveReductionProver`]), the verifier half
//! ([`InteractiveReductionVerifier`]), and their conjunction
//! ([`InteractiveReduction`]).

use crate::ReductionCore;
use crate::VerificationResult;
use crate::channel::{ProverChannel, VerifierChannel};

/// Prover half of an executable public-coin interactive oracle reduction.
pub trait InteractiveReductionProver: ReductionCore {
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

/// Executable public-coin interactive oracle reduction: both halves.
///
/// Unlike an `InteractiveArgument` whose verifier outputs accept/reject,
/// an `InteractiveReduction` verifier outputs a **new instance** of a
/// (potentially simpler) target relation. Marker conjunction of
/// [`InteractiveReductionProver`] and [`InteractiveReductionVerifier`]; the
/// blanket impl makes any type implementing both halves an `InteractiveReduction`
/// automatically.
pub trait InteractiveReduction: InteractiveReductionProver + InteractiveReductionVerifier {}

impl<T: InteractiveReductionProver + InteractiveReductionVerifier> InteractiveReduction for T {}
