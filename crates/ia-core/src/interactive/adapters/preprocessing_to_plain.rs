//! Prepared interactive adapters for preprocessing protocols.

use crate::{
    ArgumentCore, CommittedIndexBytes, IndexedInstance, InteractiveArgument, InteractiveReduction,
    Preprocessed, PreprocessingInteractiveArgument, PreprocessingInteractiveReduction,
    ProtocolCore, ProverChannel, ReductionCore, VerificationError, VerificationResult,
    VerifierChannel, VerifierKeyCommitment,
};

/// Wraps an indexed argument plus its preprocessing keys as a plain
/// [`InteractiveArgument`] whose public input is an [`IndexedInstance`].
///
/// All fields are private; both constructors derive `committed_index` from
/// `vk.committed_index()` (Invariant 6). The IA impl checks that any
/// `IndexedInstance` it receives has a matching commitment: prover-side
/// mismatch panics (programmer error); verifier-side mismatch returns
/// [`VerificationError`].
pub struct PreparedArgument<B: PreprocessingInteractiveArgument> {
    body: B,
    pk: B::ProverKey,
    vk: B::VerifierKey,
    committed_index: CommittedIndexBytes,
}

impl<B: PreprocessingInteractiveArgument> PreparedArgument<B> {
    /// Run `body.index(ix)` and store the resulting keys.
    pub fn prepare(body: B, ix: &B::Index) -> Self {
        let (pk, vk) = body.index(ix);
        let committed_index = vk.committed_index();
        Self {
            body,
            pk,
            vk,
            committed_index,
        }
    }

    /// Use externally-stored preprocessing keys. The committed index is always
    /// re-derived from `vk` to prevent callers from desyncing the cached
    /// commitment from the verifier key.
    pub fn with_keys(body: B, pk: B::ProverKey, vk: B::VerifierKey) -> Self {
        let committed_index = vk.committed_index();
        Self {
            body,
            pk,
            vk,
            committed_index,
        }
    }

    /// Pair a per-claim instance with this prepared adapter's committed index.
    pub fn indexed_instance(&self, instance: B::Instance) -> IndexedInstance<B::Instance> {
        IndexedInstance::new(self.committed_index.clone(), instance)
    }

    pub fn body(&self) -> &B {
        &self.body
    }

    pub fn prover_key(&self) -> &B::ProverKey {
        &self.pk
    }

    pub fn verifier_key(&self) -> &B::VerifierKey {
        &self.vk
    }

    pub fn committed_index(&self) -> &CommittedIndexBytes {
        &self.committed_index
    }
}

impl<B: PreprocessingInteractiveArgument> Preprocessed for PreparedArgument<B> {
    type ProverKey = B::ProverKey;
    type VerifierKey = B::VerifierKey;

    fn prover_key(&self) -> &Self::ProverKey {
        &self.pk
    }

    fn verifier_key(&self) -> &Self::VerifierKey {
        &self.vk
    }

    fn committed_index(&self) -> &CommittedIndexBytes {
        &self.committed_index
    }
}

impl<B: PreprocessingInteractiveArgument> ProtocolCore for PreparedArgument<B> {
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        self.body.protocol_id()
    }
}

impl<B: PreprocessingInteractiveArgument> ArgumentCore for PreparedArgument<B> {
    type Instance = IndexedInstance<B::Instance>;
    type Witness = B::Witness;
}

impl<B: PreprocessingInteractiveArgument> InteractiveArgument for PreparedArgument<B> {
    fn prove<P: ProverChannel>(
        &self,
        ch: &mut P,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) {
        assert!(
            instance.committed_index() == &self.committed_index,
            "PreparedArgument::prove: IndexedInstance commitment does not match stored verifier key"
        );
        self.body.prove(ch, &self.pk, instance.inner(), witness);
    }

    fn verify<V: VerifierChannel>(
        &self,
        ch: &mut V,
        instance: &Self::Instance,
    ) -> VerificationResult<()> {
        if instance.committed_index() != &self.committed_index {
            return Err(VerificationError);
        }
        self.body.verify(ch, &self.vk, instance.inner())
    }
}

/// Reduction counterpart to [`PreparedArgument`].
pub struct PreparedReduction<B: PreprocessingInteractiveReduction> {
    body: B,
    pk: B::ProverKey,
    vk: B::VerifierKey,
    committed_index: CommittedIndexBytes,
}

impl<B: PreprocessingInteractiveReduction> PreparedReduction<B> {
    pub fn prepare(body: B, ix: &B::Index) -> Self {
        let (pk, vk) = body.index(ix);
        let committed_index = vk.committed_index();
        Self {
            body,
            pk,
            vk,
            committed_index,
        }
    }

    pub fn with_keys(body: B, pk: B::ProverKey, vk: B::VerifierKey) -> Self {
        let committed_index = vk.committed_index();
        Self {
            body,
            pk,
            vk,
            committed_index,
        }
    }

    /// Pair a source instance with this prepared adapter's committed index.
    pub fn indexed_source(
        &self,
        instance: B::SourceInstance,
    ) -> IndexedInstance<B::SourceInstance> {
        IndexedInstance::new(self.committed_index.clone(), instance)
    }

    pub fn body(&self) -> &B {
        &self.body
    }

    pub fn prover_key(&self) -> &B::ProverKey {
        &self.pk
    }

    pub fn verifier_key(&self) -> &B::VerifierKey {
        &self.vk
    }

    pub fn committed_index(&self) -> &CommittedIndexBytes {
        &self.committed_index
    }
}

impl<B: PreprocessingInteractiveReduction> Preprocessed for PreparedReduction<B> {
    type ProverKey = B::ProverKey;
    type VerifierKey = B::VerifierKey;

    fn prover_key(&self) -> &Self::ProverKey {
        &self.pk
    }

    fn verifier_key(&self) -> &Self::VerifierKey {
        &self.vk
    }

    fn committed_index(&self) -> &CommittedIndexBytes {
        &self.committed_index
    }
}

impl<B: PreprocessingInteractiveReduction> ProtocolCore for PreparedReduction<B> {
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        self.body.protocol_id()
    }
}

impl<B: PreprocessingInteractiveReduction> ReductionCore for PreparedReduction<B> {
    type SourceInstance = IndexedInstance<B::SourceInstance>;
    type TargetInstance = B::TargetInstance;
    type SourceWitness = B::SourceWitness;
    type TargetWitness = B::TargetWitness;
}

impl<B: PreprocessingInteractiveReduction> InteractiveReduction for PreparedReduction<B> {
    fn prove<P: ProverChannel>(
        &self,
        ch: &mut P,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (Self::TargetInstance, Self::TargetWitness) {
        assert!(
            instance.committed_index() == &self.committed_index,
            "PreparedReduction::prove: IndexedInstance commitment does not match stored verifier key"
        );
        self.body.prove(ch, &self.pk, instance.inner(), witness)
    }

    fn verify<V: VerifierChannel>(
        &self,
        ch: &mut V,
        instance: &Self::SourceInstance,
    ) -> VerificationResult<Self::TargetInstance> {
        if instance.committed_index() != &self.committed_index {
            return Err(VerificationError);
        }
        self.body.verify(ch, &self.vk, instance.inner())
    }
}
