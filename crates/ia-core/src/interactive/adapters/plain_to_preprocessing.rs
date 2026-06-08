//! Role-specific trivial preprocessing adapters for plain protocols.

use crate::{
    ArgumentCore, ArgumentProverCore, Indexer, InteractiveArgumentProver,
    InteractiveArgumentVerifier, InteractiveReductionProver, InteractiveReductionVerifier,
    PreprocessingInteractiveArgumentProver, PreprocessingInteractiveArgumentVerifier,
    PreprocessingInteractiveReductionProver, PreprocessingInteractiveReductionVerifier,
    ProtocolCore, ProverChannel, ReductionCore, ReductionProverCore, VerificationResult,
    VerifierChannel,
};

/// Indexer for a plain protocol embedded in a preprocessing composition.
pub struct TrivialIndexer<T>(pub T);

impl<T: ProtocolCore> ProtocolCore for TrivialIndexer<T> {
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        self.0.protocol_id()
    }
}

impl<T: ArgumentCore> ArgumentCore for TrivialIndexer<T> {
    type Instance = T::Instance;
}

impl<T: ReductionCore> ReductionCore for TrivialIndexer<T> {
    type SourceInstance = T::SourceInstance;
    type TargetInstance = T::TargetInstance;
}

impl<T: ProtocolCore> Indexer for TrivialIndexer<T> {
    type Index = ();
    type ProverKey = ();
    type VerifierKey = ();

    fn preprocess(&self, _: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
        ((), ())
    }
}

/// Plain argument prover exposed through the preprocessing prover interface.
pub struct TrivialIndexedArgumentProver<P>(pub P);

impl<P: ProtocolCore> ProtocolCore for TrivialIndexedArgumentProver<P> {
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        self.0.protocol_id()
    }
}

impl<P: ArgumentCore> ArgumentCore for TrivialIndexedArgumentProver<P> {
    type Instance = P::Instance;
}

impl<P: ArgumentProverCore> ArgumentProverCore for TrivialIndexedArgumentProver<P> {
    type Witness = P::Witness;
}

impl<P: InteractiveArgumentProver> PreprocessingInteractiveArgumentProver
    for TrivialIndexedArgumentProver<P>
{
    type ProverKey = ();

    fn prove<C: ProverChannel<Unit = u8>>(
        &self,
        ch: &mut C,
        _: &Self::ProverKey,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) {
        self.0.prove(ch, instance, witness)
    }
}

/// Plain argument verifier exposed through the preprocessing verifier interface.
pub struct TrivialIndexedArgumentVerifier<V>(pub V);

impl<V: ProtocolCore> ProtocolCore for TrivialIndexedArgumentVerifier<V> {
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        self.0.protocol_id()
    }
}

impl<V: ArgumentCore> ArgumentCore for TrivialIndexedArgumentVerifier<V> {
    type Instance = V::Instance;
}

impl<V: InteractiveArgumentVerifier> PreprocessingInteractiveArgumentVerifier
    for TrivialIndexedArgumentVerifier<V>
{
    type VerifierKey = ();

    fn verify<C: VerifierChannel<Unit = u8>>(
        &self,
        ch: &mut C,
        _: &Self::VerifierKey,
        instance: &Self::Instance,
    ) -> VerificationResult<()> {
        self.0.verify(ch, instance)
    }
}

/// Plain reduction prover exposed through the preprocessing prover interface.
pub struct TrivialIndexedReductionProver<P>(pub P);

impl<P: ProtocolCore> ProtocolCore for TrivialIndexedReductionProver<P> {
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        self.0.protocol_id()
    }
}

impl<P: ReductionCore> ReductionCore for TrivialIndexedReductionProver<P> {
    type SourceInstance = P::SourceInstance;
    type TargetInstance = P::TargetInstance;
}

impl<P: ReductionProverCore> ReductionProverCore for TrivialIndexedReductionProver<P> {
    type SourceWitness = P::SourceWitness;
    type TargetWitness = P::TargetWitness;
}

impl<P: InteractiveReductionProver> PreprocessingInteractiveReductionProver
    for TrivialIndexedReductionProver<P>
{
    type ProverKey = ();

    fn prove<C: ProverChannel<Unit = u8>>(
        &self,
        ch: &mut C,
        _: &Self::ProverKey,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (Self::TargetInstance, Self::TargetWitness) {
        self.0.prove(ch, instance, witness)
    }
}

/// Plain reduction verifier exposed through the preprocessing verifier interface.
pub struct TrivialIndexedReductionVerifier<V>(pub V);

impl<V: ProtocolCore> ProtocolCore for TrivialIndexedReductionVerifier<V> {
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        self.0.protocol_id()
    }
}

impl<V: ReductionCore> ReductionCore for TrivialIndexedReductionVerifier<V> {
    type SourceInstance = V::SourceInstance;
    type TargetInstance = V::TargetInstance;
}

impl<V: InteractiveReductionVerifier> PreprocessingInteractiveReductionVerifier
    for TrivialIndexedReductionVerifier<V>
{
    type VerifierKey = ();

    fn verify<C: VerifierChannel<Unit = u8>>(
        &self,
        ch: &mut C,
        _: &Self::VerifierKey,
        instance: &Self::SourceInstance,
    ) -> VerificationResult<Self::TargetInstance> {
        self.0.verify(ch, instance)
    }
}
