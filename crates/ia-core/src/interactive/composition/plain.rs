//! Plain interactive composition impls.

use super::{ChainedReduction, ReducedArgument};
use crate::channel::{ProverChannel, VerifierChannel};
use crate::{
    ArgumentSecurity, InteractiveArgument, InteractiveReduction, ReductionSecurity,
    SecurityProfile, VerificationResult,
};

impl<First, Second> InteractiveReduction for ChainedReduction<First, Second>
where
    First: InteractiveReduction,
    Second: InteractiveReduction<
            SourceInstance = First::TargetInstance,
            SourceWitness = First::TargetWitness,
        >,
{
    fn prove<P: ProverChannel<Unit = u8>>(
        &self,
        ch: &mut P,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (Self::TargetInstance, Self::TargetWitness) {
        let (x2, w2) = self.first.prove(ch, instance, witness);
        self.second.prove(ch, &x2, &w2)
    }

    fn verify<V: VerifierChannel<Unit = u8>>(
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

impl<R, A> InteractiveArgument for ReducedArgument<R, A>
where
    R: InteractiveReduction,
    A: InteractiveArgument<Instance = R::TargetInstance, Witness = R::TargetWitness>,
{
    fn prove<P: ProverChannel<Unit = u8>>(
        &self,
        ch: &mut P,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) {
        let (x2, w2) = self.reduction.prove(ch, instance, witness);
        self.argument.prove(ch, &x2, &w2);
    }

    fn verify<V: VerifierChannel<Unit = u8>>(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ArgumentCore, ProtocolCore, ReductionCore, SecurityErrorBound, VerifierChannel};

    #[derive(Default)]
    struct SizedReduction;

    impl ProtocolCore for SizedReduction {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            b"sized-reduction"
        }
    }

    impl ReductionCore for SizedReduction {
        type SourceInstance = usize;
        type TargetInstance = usize;
        type SourceWitness = ();
        type TargetWitness = ();
    }

    impl InteractiveReduction for SizedReduction {
        fn prove<P: ProverChannel<Unit = u8>>(
            &self,
            _ch: &mut P,
            instance: &Self::SourceInstance,
            _witness: &Self::SourceWitness,
        ) -> (Self::TargetInstance, Self::TargetWitness) {
            (instance + 7, ())
        }

        fn verify<V: VerifierChannel<Unit = u8>>(
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

    impl ProtocolCore for BoundedArgument {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            b"bounded-argument"
        }
    }

    impl ArgumentCore for BoundedArgument {
        type Instance = usize;
        type Witness = ();
    }

    impl InteractiveArgument for BoundedArgument {
        fn prove<P: ProverChannel<Unit = u8>>(
            &self,
            _ch: &mut P,
            _instance: &Self::Instance,
            _witness: &Self::Witness,
        ) {
        }

        fn verify<V: VerifierChannel<Unit = u8>>(
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
