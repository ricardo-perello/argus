//! Trivial preprocessing adapters for plain protocols in mixed compositions.

use crate::{
    ArgumentCore, InteractiveArgumentProver, InteractiveArgumentVerifier,
    InteractiveReductionProver, InteractiveReductionVerifier, PreprocessingCore,
    PreprocessingInteractiveArgumentProver, PreprocessingInteractiveArgumentVerifier,
    PreprocessingInteractiveReductionProver, PreprocessingInteractiveReductionVerifier,
    ProtocolCore, ProverChannel, ReductionCore, VerificationResult, VerifierChannel,
};

/// Wraps a plain interactive argument as a preprocessing interactive argument
/// with unit index and unit keys (empty committed index).
///
/// Intended for the *inner* slot of a heterogeneous preprocessing composition so that
/// a plain protocol can sit beside a real indexed component. Wrapping a plain
/// protocol with this adapter and pushing it through preprocessing DSFS at the top
/// level will NOT produce the same bytes as the plain DSFS path — the preprocessing
/// transcript absorbs `IndexedInstance { committed_index: empty, instance: x }`
/// instead of the bare `x`. Use the plain DSFS path for top-level plain
/// protocols.
///
/// The core impls only need [`ArgumentCore`], and each leaf half only needs the
/// matching inner half, so wrapping a prover-only (or verifier-only) inner
/// protocol yields a prover-only (or verifier-only) adapter.
pub struct TrivialIndexedArgument<A>(pub A);

impl<A: ProtocolCore> ProtocolCore for TrivialIndexedArgument<A> {
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        self.0.protocol_id()
    }
}

impl<A: ArgumentCore> ArgumentCore for TrivialIndexedArgument<A> {
    type Instance = A::Instance;
    type Witness = A::Witness;
}

impl<A: ArgumentCore> PreprocessingCore for TrivialIndexedArgument<A> {
    type Index = ();
    type ProverKey = ();
    type VerifierKey = ();

    fn preprocess(&self, _: &()) -> ((), ()) {
        ((), ())
    }
}

impl<A: InteractiveArgumentProver> PreprocessingInteractiveArgumentProver
    for TrivialIndexedArgument<A>
{
    fn prove<P: ProverChannel<Unit = u8>>(
        &self,
        ch: &mut P,
        _: &Self::ProverKey,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) {
        self.0.prove(ch, instance, witness)
    }
}

impl<A: InteractiveArgumentVerifier> PreprocessingInteractiveArgumentVerifier
    for TrivialIndexedArgument<A>
{
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

impl<R: ProtocolCore> ProtocolCore for TrivialIndexedReduction<R> {
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        self.0.protocol_id()
    }
}

impl<R: ReductionCore> ReductionCore for TrivialIndexedReduction<R> {
    type SourceInstance = R::SourceInstance;
    type TargetInstance = R::TargetInstance;
    type SourceWitness = R::SourceWitness;
    type TargetWitness = R::TargetWitness;
}

impl<R: ReductionCore> PreprocessingCore for TrivialIndexedReduction<R> {
    type Index = ();
    type ProverKey = ();
    type VerifierKey = ();

    fn preprocess(&self, _: &()) -> ((), ()) {
        ((), ())
    }
}

impl<R: InteractiveReductionProver> PreprocessingInteractiveReductionProver
    for TrivialIndexedReduction<R>
{
    fn prove<P: ProverChannel<Unit = u8>>(
        &self,
        ch: &mut P,
        _: &Self::ProverKey,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (Self::TargetInstance, Self::TargetWitness) {
        self.0.prove(ch, instance, witness)
    }
}

impl<R: InteractiveReductionVerifier> PreprocessingInteractiveReductionVerifier
    for TrivialIndexedReduction<R>
{
    fn verify<V: VerifierChannel<Unit = u8>>(
        &self,
        ch: &mut V,
        _: &Self::VerifierKey,
        instance: &Self::SourceInstance,
    ) -> VerificationResult<Self::TargetInstance> {
        self.0.verify(ch, instance)
    }
}
