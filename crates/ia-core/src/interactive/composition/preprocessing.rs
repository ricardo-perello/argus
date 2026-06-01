//! Preprocessing interactive composition impls.

use crate::{
    PreprocessingCore, PreprocessingInteractiveArgument, PreprocessingInteractiveReduction,
    ProverChannel, VerificationResult, VerifierChannel,
};

use super::{ChainedReduction, ReducedArgument};

impl<First, Second> PreprocessingCore for ChainedReduction<First, Second>
where
    First: PreprocessingInteractiveReduction,
    Second: PreprocessingInteractiveReduction<
            SourceInstance = First::TargetInstance,
            SourceWitness = First::TargetWitness,
        >,
{
    type Index = (First::Index, Second::Index);
    type ProverKey = (First::ProverKey, Second::ProverKey);
    type VerifierKey = (First::VerifierKey, Second::VerifierKey);

    fn index(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
        let (pk1, vk1) = self.first.index(&ix.0);
        let (pk2, vk2) = self.second.index(&ix.1);
        ((pk1, pk2), (vk1, vk2))
    }
}

impl<First, Second> PreprocessingInteractiveReduction for ChainedReduction<First, Second>
where
    First: PreprocessingInteractiveReduction,
    Second: PreprocessingInteractiveReduction<
            SourceInstance = First::TargetInstance,
            SourceWitness = First::TargetWitness,
        >,
{
    fn prove<P: ProverChannel<Unit = u8>>(
        &self,
        ch: &mut P,
        pk: &Self::ProverKey,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (Self::TargetInstance, Self::TargetWitness) {
        let (x2, w2) = self.first.prove(ch, &pk.0, instance, witness);
        self.second.prove(ch, &pk.1, &x2, &w2)
    }

    fn verify<V: VerifierChannel<Unit = u8>>(
        &self,
        ch: &mut V,
        vk: &Self::VerifierKey,
        instance: &Self::SourceInstance,
    ) -> VerificationResult<Self::TargetInstance> {
        let intermediate = self.first.verify(ch, &vk.0, instance)?;
        self.second.verify(ch, &vk.1, &intermediate)
    }
}

impl<R, A> PreprocessingCore for ReducedArgument<R, A>
where
    R: PreprocessingInteractiveReduction,
    A: PreprocessingInteractiveArgument<Instance = R::TargetInstance, Witness = R::TargetWitness>,
{
    type Index = (R::Index, A::Index);
    type ProverKey = (R::ProverKey, A::ProverKey);
    type VerifierKey = (R::VerifierKey, A::VerifierKey);

    fn index(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
        let (pk1, vk1) = self.reduction.index(&ix.0);
        let (pk2, vk2) = self.argument.index(&ix.1);
        ((pk1, pk2), (vk1, vk2))
    }
}

impl<R, A> PreprocessingInteractiveArgument for ReducedArgument<R, A>
where
    R: PreprocessingInteractiveReduction,
    A: PreprocessingInteractiveArgument<Instance = R::TargetInstance, Witness = R::TargetWitness>,
{
    fn prove<P: ProverChannel<Unit = u8>>(
        &self,
        ch: &mut P,
        pk: &Self::ProverKey,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) {
        let (x2, w2) = self.reduction.prove(ch, &pk.0, instance, witness);
        self.argument.prove(ch, &pk.1, &x2, &w2);
    }

    fn verify<V: VerifierChannel<Unit = u8>>(
        &self,
        ch: &mut V,
        vk: &Self::VerifierKey,
        instance: &Self::Instance,
    ) -> VerificationResult<()> {
        let target_instance = self.reduction.verify(ch, &vk.0, instance)?;
        self.argument.verify(ch, &vk.1, &target_instance)
    }
}
