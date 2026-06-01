//! Trivial preprocessing adapters for plain protocols in mixed compositions.

use crate::{
    ArgumentCore, InteractiveArgument, InteractiveReduction, PreprocessingCore,
    PreprocessingInteractiveArgument, PreprocessingInteractiveReduction, ProtocolCore,
    ProverChannel, ReductionCore, VerificationResult, VerifierChannel,
};

/// Wraps a plain [`InteractiveArgument`] as an [`PreprocessingInteractiveArgument`]
/// with unit index and unit keys (empty committed index).
///
/// Intended for the *inner* slot of a heterogeneous preprocessing composition so that
/// a plain protocol can sit beside a real indexed component. Wrapping a plain
/// protocol with this adapter and pushing it through prepared DSFS at the top
/// level will NOT produce the same bytes as the plain DSFS path — the prepared
/// transcript absorbs `IndexedInstance { committed_index: empty, instance: x }`
/// instead of the bare `x`. Use the plain DSFS path for top-level plain
/// protocols.
pub struct TrivialIndexedArgument<A>(pub A);

impl<A: InteractiveArgument> ProtocolCore for TrivialIndexedArgument<A> {
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        self.0.protocol_id()
    }
}

impl<A: InteractiveArgument> ArgumentCore for TrivialIndexedArgument<A> {
    type Instance = A::Instance;
    type Witness = A::Witness;
}

impl<A: InteractiveArgument> PreprocessingCore for TrivialIndexedArgument<A> {
    type Index = ();
    type ProverKey = ();
    type VerifierKey = ();

    fn preprocess(&self, _: &()) -> ((), ()) {
        ((), ())
    }
}

impl<A: InteractiveArgument> PreprocessingInteractiveArgument for TrivialIndexedArgument<A> {
    fn prove<P: ProverChannel<Unit = u8>>(
        &self,
        ch: &mut P,
        _: &Self::ProverKey,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) {
        self.0.prove(ch, instance, witness)
    }

    fn verify<V: VerifierChannel<Unit = u8>>(
        &self,
        ch: &mut V,
        _: &Self::VerifierKey,
        instance: &Self::Instance,
    ) -> VerificationResult<()> {
        self.0.verify(ch, instance)
    }
}

/// Reduction counterpart to [`TrivialIndexedArgument`].
pub struct TrivialIndexedReduction<R>(pub R);

impl<R: InteractiveReduction> ProtocolCore for TrivialIndexedReduction<R> {
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        self.0.protocol_id()
    }
}

impl<R: InteractiveReduction> ReductionCore for TrivialIndexedReduction<R> {
    type SourceInstance = R::SourceInstance;
    type TargetInstance = R::TargetInstance;
    type SourceWitness = R::SourceWitness;
    type TargetWitness = R::TargetWitness;
}

impl<R: InteractiveReduction> PreprocessingCore for TrivialIndexedReduction<R> {
    type Index = ();
    type ProverKey = ();
    type VerifierKey = ();

    fn preprocess(&self, _: &()) -> ((), ()) {
        ((), ())
    }
}

impl<R: InteractiveReduction> PreprocessingInteractiveReduction for TrivialIndexedReduction<R> {
    fn prove<P: ProverChannel<Unit = u8>>(
        &self,
        ch: &mut P,
        _: &Self::ProverKey,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (Self::TargetInstance, Self::TargetWitness) {
        self.0.prove(ch, instance, witness)
    }

    fn verify<V: VerifierChannel<Unit = u8>>(
        &self,
        ch: &mut V,
        _: &Self::VerifierKey,
        instance: &Self::SourceInstance,
    ) -> VerificationResult<Self::TargetInstance> {
        self.0.verify(ch, instance)
    }
}
