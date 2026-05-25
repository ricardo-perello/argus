//! Sequential composition of reductions and reduced arguments.

extern crate alloc;

use alloc::vec::Vec;

use crate::VerificationResult;
use crate::argument::InteractiveArgument;
use crate::channel::{ProverChannel, VerifierChannel};
use crate::protocol::{ArgumentBody, ProtocolBody, ReductionBody};
use crate::reduction::InteractiveReduction;
use crate::security::{ArgumentSecurity, ReductionSecurity, SecurityProfile};

/// Derives a variable-length protocol identifier from two sub-protocol IDs and a
/// domain-separation tag, using length-prefixed concatenation:
///   `tag || LE32(|first|) || first || LE32(|second|) || second`
/// This encoding is injective — no two distinct `(tag, first, second)` triples
/// produce the same byte string — so it's a safe input to the DSFS derivation.
pub(crate) fn derive_composition_id(tag: u8, first: &[u8], second: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + first.len() + 4 + second.len());
    out.push(tag);
    out.extend_from_slice(&(first.len() as u32).to_le_bytes());
    out.extend_from_slice(first);
    out.extend_from_slice(&(second.len() as u32).to_le_bytes());
    out.extend_from_slice(second);
    out
}

/// Sequential composition of two interactive reductions: IR . IR -> IR.
///
/// `First` reduces `(SourceInstance, SourceWitness)` into an intermediate
/// relation; `Second` reduces that intermediate relation into the final
/// `(TargetInstance, TargetWitness)`.
pub struct ChainedReduction<First, Second> {
    pub first: First,
    pub second: Second,
}

impl<First, Second> ChainedReduction<First, Second> {
    pub fn new(first: First, second: Second) -> Self {
        Self { first, second }
    }
}

impl<First, Second> ProtocolBody for ChainedReduction<First, Second>
where
    First: ProtocolBody,
    Second: ProtocolBody,
{
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        derive_composition_id(
            0x01,
            self.first.protocol_id().as_ref(),
            self.second.protocol_id().as_ref(),
        )
    }
}

impl<First, Second> ReductionBody for ChainedReduction<First, Second>
where
    First: ReductionBody,
    Second:
        ReductionBody<SourceInstance = First::TargetInstance, SourceWitness = First::TargetWitness>,
{
    type SourceInstance = First::SourceInstance;
    type TargetInstance = Second::TargetInstance;
    type SourceWitness = First::SourceWitness;
    type TargetWitness = Second::TargetWitness;
}

impl<First, Second> InteractiveReduction for ChainedReduction<First, Second>
where
    First: InteractiveReduction,
    Second: InteractiveReduction<
            SourceInstance = First::TargetInstance,
            SourceWitness = First::TargetWitness,
        >,
{
    fn prove<P: ProverChannel>(
        &self,
        ch: &mut P,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (Self::TargetInstance, Self::TargetWitness) {
        let (x2, w2) = self.first.prove(ch, instance, witness);
        self.second.prove(ch, &x2, &w2)
    }

    fn verify<V: VerifierChannel>(
        &self,
        ch: &mut V,
        instance: &Self::SourceInstance,
    ) -> VerificationResult<Self::TargetInstance> {
        let intermediate = self.first.verify(ch, instance)?;
        self.second.verify(ch, &intermediate)
    }
}

impl<First, Second> ReductionSecurity for ChainedReduction<First, Second>
where
    First: InteractiveReduction + ReductionSecurity,
    Second: InteractiveReduction<
            SourceInstance = First::TargetInstance,
            SourceWitness = First::TargetWitness,
        > + ReductionSecurity<SourceBound = First::TargetBound>,
{
    type SourceParams = First::SourceParams;
    type SourceBound = First::SourceBound;
    type TargetBound = Second::TargetBound;

    fn source_security_params(&self, instance: &Self::SourceInstance) -> Self::SourceParams {
        self.first.source_security_params(instance)
    }

    fn source_bound_for_source_params(&self, params: &Self::SourceParams) -> Self::SourceBound {
        self.first.source_bound_for_source_params(params)
    }

    fn target_bound_for_source_params(&self, params: &Self::SourceParams) -> Self::TargetBound {
        let intermediate_bound = self.first.target_bound_for_source_params(params);
        self.second
            .target_bound_for_source_bound(&intermediate_bound)
    }

    fn target_bound_for_source_bound(&self, bound: &Self::SourceBound) -> Self::TargetBound {
        let intermediate_bound = self.first.target_bound_for_source_bound(bound);
        self.second
            .target_bound_for_source_bound(&intermediate_bound)
    }

    fn profile_for_source_params(&self, params: &Self::SourceParams) -> SecurityProfile {
        let first_profile = self.first.profile_for_source_params(params);
        let intermediate_bound = self.first.target_bound_for_source_params(params);
        first_profile.compose(&self.second.profile_for_source_bound(&intermediate_bound))
    }

    fn profile_for_source_bound(&self, bound: &Self::SourceBound) -> SecurityProfile {
        let first_profile = self.first.profile_for_source_bound(bound);
        let intermediate_bound = self.first.target_bound_for_source_bound(bound);
        first_profile.compose(&self.second.profile_for_source_bound(&intermediate_bound))
    }
}

/// Default impl so `ChainedReduction<F, S>` can be zero-sized-constructed when
/// both subcomponents are `Default`.
impl<First: Default, Second: Default> Default for ChainedReduction<First, Second> {
    fn default() -> Self {
        Self {
            first: First::default(),
            second: Second::default(),
        }
    }
}

/// Sequential composition of an interactive reduction followed by an
/// interactive argument: IR . IA -> IA.
///
/// `Reduction` reduces the source relation into a target relation whose
/// instance and witness types match the `Argument`.  The composed protocol
/// is itself an interactive argument (the verifier outputs accept/reject).
pub struct ReducedArgument<Reduction, Argument> {
    pub reduction: Reduction,
    pub argument: Argument,
}

impl<R, A> ReducedArgument<R, A> {
    pub fn new(reduction: R, argument: A) -> Self {
        Self {
            reduction,
            argument,
        }
    }
}

impl<R, A> ProtocolBody for ReducedArgument<R, A>
where
    R: ProtocolBody,
    A: ProtocolBody,
{
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        derive_composition_id(
            0x02,
            self.reduction.protocol_id().as_ref(),
            self.argument.protocol_id().as_ref(),
        )
    }
}

impl<R, A> ArgumentBody for ReducedArgument<R, A>
where
    R: ReductionBody,
    A: ArgumentBody<Instance = R::TargetInstance, Witness = R::TargetWitness>,
{
    type Instance = R::SourceInstance;
    type Witness = R::SourceWitness;
}

impl<R, A> InteractiveArgument for ReducedArgument<R, A>
where
    R: InteractiveReduction,
    A: InteractiveArgument<Instance = R::TargetInstance, Witness = R::TargetWitness>,
{
    fn prove<P: ProverChannel>(
        &self,
        ch: &mut P,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) {
        let (x2, w2) = self.reduction.prove(ch, instance, witness);
        self.argument.prove(ch, &x2, &w2);
    }

    fn verify<V: VerifierChannel>(
        &self,
        ch: &mut V,
        instance: &Self::Instance,
    ) -> VerificationResult<()> {
        let target_instance = self.reduction.verify(ch, instance)?;
        self.argument.verify(ch, &target_instance)
    }
}

impl<R, A> ArgumentSecurity for ReducedArgument<R, A>
where
    R: InteractiveReduction + ReductionSecurity,
    A: InteractiveArgument<Instance = R::TargetInstance, Witness = R::TargetWitness>
        + ArgumentSecurity<InstanceBound = R::TargetBound>,
{
    type InstanceParams = R::SourceParams;
    type InstanceBound = R::SourceBound;

    fn instance_security_params(&self, instance: &Self::Instance) -> Self::InstanceParams {
        self.reduction.source_security_params(instance)
    }

    fn instance_bound_for_instance_params(
        &self,
        params: &Self::InstanceParams,
    ) -> Self::InstanceBound {
        self.reduction.source_bound_for_source_params(params)
    }

    fn profile_for_instance_params(&self, params: &Self::InstanceParams) -> SecurityProfile {
        let reduction_profile = self.reduction.profile_for_source_params(params);
        let target_bound = self.reduction.target_bound_for_source_params(params);
        reduction_profile.compose(&self.argument.profile_for_instance_bound(&target_bound))
    }

    fn profile_for_instance_bound(&self, bound: &Self::InstanceBound) -> SecurityProfile {
        let reduction_profile = self.reduction.profile_for_source_bound(bound);
        let target_bound = self.reduction.target_bound_for_source_bound(bound);
        reduction_profile.compose(&self.argument.profile_for_instance_bound(&target_bound))
    }
}

impl<R: Default, A: Default> Default for ReducedArgument<R, A> {
    fn default() -> Self {
        Self {
            reduction: R::default(),
            argument: A::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SecurityErrorBound, VerifierChannel};

    #[derive(Default)]
    struct SizedReduction;

    impl ProtocolBody for SizedReduction {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            b"sized-reduction"
        }
    }

    impl ReductionBody for SizedReduction {
        type SourceInstance = usize;
        type TargetInstance = usize;
        type SourceWitness = ();
        type TargetWitness = ();
    }

    impl InteractiveReduction for SizedReduction {
        fn prove<P: ProverChannel>(
            &self,
            _ch: &mut P,
            instance: &Self::SourceInstance,
            _witness: &Self::SourceWitness,
        ) -> (Self::TargetInstance, Self::TargetWitness) {
            (instance + 7, ())
        }

        fn verify<V: VerifierChannel>(
            &self,
            _ch: &mut V,
            instance: &Self::SourceInstance,
        ) -> VerificationResult<Self::TargetInstance> {
            Ok(instance + 7)
        }
    }

    impl ReductionSecurity for SizedReduction {
        type SourceParams = usize;
        type SourceBound = usize;
        type TargetBound = usize;

        fn source_security_params(&self, instance: &Self::SourceInstance) -> Self::SourceParams {
            *instance
        }

        fn source_bound_for_source_params(&self, params: &Self::SourceParams) -> Self::SourceBound {
            *params
        }

        fn target_bound_for_source_params(&self, params: &Self::SourceParams) -> Self::TargetBound {
            *params + 7
        }

        fn target_bound_for_source_bound(&self, bound: &Self::SourceBound) -> Self::TargetBound {
            *bound + 7
        }

        fn profile_for_source_params(&self, params: &Self::SourceParams) -> SecurityProfile {
            let eps = *params as f64 / 1000.0;
            SecurityProfile {
                plain_soundness_error: SecurityErrorBound::zero(),
                rbr_soundness_errors: alloc::vec![SecurityErrorBound::new(move |_| eps)],
                rbr_knowledge_soundness_errors: alloc::vec![],
                hvzk_error: SecurityErrorBound::zero(),
                verifier_challenge_lengths: alloc::vec![1],
            }
        }

        fn profile_for_source_bound(&self, bound: &Self::SourceBound) -> SecurityProfile {
            self.profile_for_source_params(bound)
        }
    }

    #[derive(Default)]
    struct BoundedArgument;

    impl ProtocolBody for BoundedArgument {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            b"bounded-argument"
        }
    }

    impl ArgumentBody for BoundedArgument {
        type Instance = usize;
        type Witness = ();
    }

    impl InteractiveArgument for BoundedArgument {
        fn prove<P: ProverChannel>(
            &self,
            _ch: &mut P,
            _instance: &Self::Instance,
            _witness: &Self::Witness,
        ) {
        }

        fn verify<V: VerifierChannel>(
            &self,
            _ch: &mut V,
            _instance: &Self::Instance,
        ) -> VerificationResult<()> {
            Ok(())
        }
    }

    impl ArgumentSecurity for BoundedArgument {
        type InstanceParams = usize;
        type InstanceBound = usize;

        fn instance_security_params(&self, instance: &Self::Instance) -> Self::InstanceParams {
            *instance
        }

        fn instance_bound_for_instance_params(
            &self,
            params: &Self::InstanceParams,
        ) -> Self::InstanceBound {
            *params
        }

        fn profile_for_instance_params(&self, params: &Self::InstanceParams) -> SecurityProfile {
            let eps = *params as f64 / 10_000.0;
            SecurityProfile {
                plain_soundness_error: SecurityErrorBound::zero(),
                rbr_soundness_errors: alloc::vec![SecurityErrorBound::new(move |_| eps)],
                rbr_knowledge_soundness_errors: alloc::vec![],
                hvzk_error: SecurityErrorBound::zero(),
                verifier_challenge_lengths: alloc::vec![1],
            }
        }

        fn profile_for_instance_bound(&self, bound: &Self::InstanceBound) -> SecurityProfile {
            let eps = *bound as f64 / 100.0;
            SecurityProfile {
                plain_soundness_error: SecurityErrorBound::zero(),
                rbr_soundness_errors: alloc::vec![SecurityErrorBound::new(move |_| eps)],
                rbr_knowledge_soundness_errors: alloc::vec![],
                hvzk_error: SecurityErrorBound::zero(),
                verifier_challenge_lengths: alloc::vec![1],
            }
        }
    }

    #[test]
    fn reduced_argument_security_uses_intermediate_target_bound() {
        let protocol = ReducedArgument::new(SizedReduction, BoundedArgument);
        let profile = protocol.profile_for_concrete_instance(&3);

        assert_eq!(profile.rbr_soundness_errors.len(), 2);
        assert!((profile.sr_soundness_error(0) - 0.103).abs() < 1e-12);
    }
}
