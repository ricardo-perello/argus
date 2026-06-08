//! Preprocessing interactive composition impls.

use crate::{
    Indexer, PreprocessingInteractiveArgumentProver, PreprocessingInteractiveArgumentVerifier,
    PreprocessingInteractiveReductionProver, PreprocessingInteractiveReductionVerifier,
    ProverChannel, VerificationResult, VerifierChannel,
};

use super::{ChainedReduction, ReducedArgument};

impl<First, Second> Indexer for ChainedReduction<First, Second>
where
    First: Indexer,
    Second: Indexer,
{
    type Index = (First::Index, Second::Index);
    type ProverKey = (First::ProverKey, Second::ProverKey);
    type VerifierKey = (First::VerifierKey, Second::VerifierKey);

    fn preprocess(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
        let (pk1, vk1) = self.first.preprocess(&ix.0);
        let (pk2, vk2) = self.second.preprocess(&ix.1);
        ((pk1, pk2), (vk1, vk2))
    }
}

impl<First, Second> PreprocessingInteractiveReductionProver for ChainedReduction<First, Second>
where
    First: PreprocessingInteractiveReductionProver,
    Second: PreprocessingInteractiveReductionProver<
            SourceInstance = First::TargetInstance,
            SourceWitness = First::TargetWitness,
        >,
{
    type ProverKey = (First::ProverKey, Second::ProverKey);

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
}

impl<First, Second> PreprocessingInteractiveReductionVerifier for ChainedReduction<First, Second>
where
    First: PreprocessingInteractiveReductionVerifier,
    Second: PreprocessingInteractiveReductionVerifier<SourceInstance = First::TargetInstance>,
{
    type VerifierKey = (First::VerifierKey, Second::VerifierKey);

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

impl<R, A> Indexer for ReducedArgument<R, A>
where
    R: Indexer,
    A: Indexer,
{
    type Index = (R::Index, A::Index);
    type ProverKey = (R::ProverKey, A::ProverKey);
    type VerifierKey = (R::VerifierKey, A::VerifierKey);

    fn preprocess(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
        let (pk1, vk1) = self.reduction.preprocess(&ix.0);
        let (pk2, vk2) = self.argument.preprocess(&ix.1);
        ((pk1, pk2), (vk1, vk2))
    }
}

impl<R, A> PreprocessingInteractiveArgumentProver for ReducedArgument<R, A>
where
    R: PreprocessingInteractiveReductionProver,
    A: PreprocessingInteractiveArgumentProver<
            Instance = R::TargetInstance,
            Witness = R::TargetWitness,
        >,
{
    type ProverKey = (R::ProverKey, A::ProverKey);

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
}

impl<R, A> PreprocessingInteractiveArgumentVerifier for ReducedArgument<R, A>
where
    R: PreprocessingInteractiveReductionVerifier,
    A: PreprocessingInteractiveArgumentVerifier<Instance = R::TargetInstance>,
{
    type VerifierKey = (R::VerifierKey, A::VerifierKey);

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
