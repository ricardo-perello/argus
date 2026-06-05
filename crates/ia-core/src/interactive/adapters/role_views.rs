//! Role-view adapters for full interactive protocol bodies.
//!
//! These wrappers are an ergonomic layer over the prover/verifier split: start
//! from a full body and expose only one executable half to downstream code. They
//! are useful at deployment and example boundaries, where one party should be
//! handed a prover-shaped or verifier-shaped value.
//!
//! They are not the same as authoring a genuinely prover-only or verifier-only
//! body. A `VerifierOnly<FullProtocol>` still contains `FullProtocol`; it only
//! hides the opposite executable method at the wrapper type. If a caller must
//! depend on the verifier algorithm without depending on the prover algorithm
//! (for example recursion/accumulation), implement the verifier half directly.

use crate::{
    ArgumentCore, InteractiveArgumentProver, InteractiveArgumentVerifier,
    InteractiveReductionProver, InteractiveReductionVerifier, PreprocessingCore,
    PreprocessingInteractiveArgumentProver, PreprocessingInteractiveArgumentVerifier,
    PreprocessingInteractiveReductionProver, PreprocessingInteractiveReductionVerifier,
    ProtocolCore, ProverChannel, ReductionCore, VerificationResult, VerifierChannel,
};

/// Prover-shaped view of an interactive protocol body.
///
/// Construct with [`IntoProver::into_prover`]. The wrapper forwards protocol
/// identity and shape metadata, but implements only prover executable traits.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProverOnly<T>(pub T);

/// Verifier-shaped view of an interactive protocol body.
///
/// Construct with [`IntoVerifier::into_verifier`]. The wrapper forwards protocol
/// identity and shape metadata, but implements only verifier executable traits.
#[derive(Clone, Copy, Debug, Default)]
pub struct VerifierOnly<T>(pub T);

/// Extension trait for constructing [`ProverOnly`] role views.
pub trait IntoProver: ProtocolCore + Sized {
    fn into_prover(self) -> ProverOnly<Self> {
        ProverOnly(self)
    }
}

impl<T: ProtocolCore> IntoProver for T {}

/// Extension trait for constructing [`VerifierOnly`] role views.
pub trait IntoVerifier: ProtocolCore + Sized {
    fn into_verifier(self) -> VerifierOnly<Self> {
        VerifierOnly(self)
    }
}

impl<T: ProtocolCore> IntoVerifier for T {}

impl<T: ProtocolCore> ProtocolCore for ProverOnly<T> {
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        self.0.protocol_id()
    }
}

impl<T: ProtocolCore> ProtocolCore for VerifierOnly<T> {
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        self.0.protocol_id()
    }
}

impl<T: ArgumentCore> ArgumentCore for ProverOnly<T> {
    type Instance = T::Instance;
    type Witness = T::Witness;
}

impl<T: ArgumentCore> ArgumentCore for VerifierOnly<T> {
    type Instance = T::Instance;
    type Witness = T::Witness;
}

impl<T: ReductionCore> ReductionCore for ProverOnly<T> {
    type SourceInstance = T::SourceInstance;
    type TargetInstance = T::TargetInstance;
    type SourceWitness = T::SourceWitness;
    type TargetWitness = T::TargetWitness;
}

impl<T: ReductionCore> ReductionCore for VerifierOnly<T> {
    type SourceInstance = T::SourceInstance;
    type TargetInstance = T::TargetInstance;
    type SourceWitness = T::SourceWitness;
    type TargetWitness = T::TargetWitness;
}

impl<T: PreprocessingCore> PreprocessingCore for ProverOnly<T> {
    type Index = T::Index;
    type ProverKey = T::ProverKey;
    type VerifierKey = T::VerifierKey;

    fn preprocess(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
        self.0.preprocess(ix)
    }
}

impl<T: PreprocessingCore> PreprocessingCore for VerifierOnly<T> {
    type Index = T::Index;
    type ProverKey = T::ProverKey;
    type VerifierKey = T::VerifierKey;

    fn preprocess(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
        self.0.preprocess(ix)
    }
}

impl<T: InteractiveArgumentProver> InteractiveArgumentProver for ProverOnly<T> {
    fn prove<P: ProverChannel<Unit = u8>>(
        &self,
        ch: &mut P,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) {
        self.0.prove(ch, instance, witness)
    }
}

impl<T: InteractiveArgumentVerifier> InteractiveArgumentVerifier for VerifierOnly<T> {
    fn verify<V: VerifierChannel<Unit = u8>>(
        &self,
        ch: &mut V,
        instance: &Self::Instance,
    ) -> VerificationResult<()> {
        self.0.verify(ch, instance)
    }
}

impl<T: InteractiveReductionProver> InteractiveReductionProver for ProverOnly<T> {
    fn prove<P: ProverChannel<Unit = u8>>(
        &self,
        ch: &mut P,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (Self::TargetInstance, Self::TargetWitness) {
        self.0.prove(ch, instance, witness)
    }
}

impl<T: InteractiveReductionVerifier> InteractiveReductionVerifier for VerifierOnly<T> {
    fn verify<V: VerifierChannel<Unit = u8>>(
        &self,
        ch: &mut V,
        instance: &Self::SourceInstance,
    ) -> VerificationResult<Self::TargetInstance> {
        self.0.verify(ch, instance)
    }
}

impl<T: PreprocessingInteractiveArgumentProver> PreprocessingInteractiveArgumentProver
    for ProverOnly<T>
{
    fn prove<P: ProverChannel<Unit = u8>>(
        &self,
        ch: &mut P,
        pk: &Self::ProverKey,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) {
        self.0.prove(ch, pk, instance, witness)
    }
}

impl<T: PreprocessingInteractiveArgumentVerifier> PreprocessingInteractiveArgumentVerifier
    for VerifierOnly<T>
{
    fn verify<V: VerifierChannel<Unit = u8>>(
        &self,
        ch: &mut V,
        vk: &Self::VerifierKey,
        instance: &Self::Instance,
    ) -> VerificationResult<()> {
        self.0.verify(ch, vk, instance)
    }
}

impl<T: PreprocessingInteractiveReductionProver> PreprocessingInteractiveReductionProver
    for ProverOnly<T>
{
    fn prove<P: ProverChannel<Unit = u8>>(
        &self,
        ch: &mut P,
        pk: &Self::ProverKey,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (Self::TargetInstance, Self::TargetWitness) {
        self.0.prove(ch, pk, instance, witness)
    }
}

impl<T: PreprocessingInteractiveReductionVerifier> PreprocessingInteractiveReductionVerifier
    for VerifierOnly<T>
{
    fn verify<V: VerifierChannel<Unit = u8>>(
        &self,
        ch: &mut V,
        vk: &Self::VerifierKey,
        instance: &Self::SourceInstance,
    ) -> VerificationResult<Self::TargetInstance> {
        self.0.verify(ch, vk, instance)
    }
}
