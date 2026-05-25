//! Indexed (preprocessed) interactive arguments and reductions.
//!
//! Plain protocols implement [`InteractiveArgument`] / [`InteractiveReduction`].
//! Protocols with real preprocessing implement [`IndexedInteractiveArgument`] /
//! [`IndexedInteractiveReduction`]: an indexer splits the relation into a
//! prover key and a verifier key, and prove/verify execute keyed.
//!
//! Once preprocessing keys exist, [`PreparedArgument`] / [`PreparedReduction`]
//! wrap an indexed protocol as an ordinary IA/IR whose public input is an
//! [`IndexedInstance`] pairing the per-claim instance with a canonical
//! commitment to the verifier index. That lets backends bind the committed
//! index through the same public-input absorption path they already use.

extern crate alloc;

use alloc::vec::Vec;

use crate::compose::derive_composition_id;
use crate::{
    ChainedReduction, Encoding, InteractiveArgument, InteractiveReduction, ProverChannel,
    ReducedArgument, VerificationError, VerificationResult, VerifierChannel,
};

// ---------------------------------------------------------------------------
// Committed verifier index
// ---------------------------------------------------------------------------

/// Owned, length-prefixed bytes that backends absorb to bind the verifier index.
///
/// The wrapper exists so that the transcript input is canonical and does not
/// rely on the raw-byte identity encoding of `Vec<u8>`. [`CommittedIndexBytes`]
/// encodes as `u64_le(length) || bytes`, which is prefix-free.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommittedIndexBytes(Vec<u8>);

impl CommittedIndexBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn empty() -> Self {
        Self(Vec::new())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Encoding<[u8]> for CommittedIndexBytes {
    fn encode(&self) -> impl AsRef<[u8]> {
        let len = u64::try_from(self.0.len()).expect("committed index length exceeds u64");
        let mut out = Vec::with_capacity(8 + self.0.len());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&self.0);
        out
    }
}

/// Public bytes that DSFS (or any other backend) absorbs before the first
/// challenge to bind the preprocessed verifier index.
///
/// Implementors may return the full verifier key bytes, a hash, or a small
/// tuple of root/digest commitments — whatever is appropriate for the soundness
/// argument of the surrounding protocol. The only invariants are that the
/// returned bytes are deterministic and canonical for a given verifier key.
pub trait VerifierKeyCommitment {
    fn committed_index(&self) -> CommittedIndexBytes;
}

impl VerifierKeyCommitment for () {
    fn committed_index(&self) -> CommittedIndexBytes {
        CommittedIndexBytes::empty()
    }
}

/// Capability for any wrapper that carries preprocessing keys generated from
/// an indexer.
///
/// Implemented by `PreparedArgument` / `PreparedReduction` at the IA/IR layer,
/// and by `PreparedDsfs` / `PreparedDsfsReduction` at the NARG layer. A single
/// trait so consumers asking "where do the keys live?" have one answer
/// regardless of which plane the wrapper sits on.
///
/// `prover_key` returns secret material — callers must not serialize or
/// transport it. `verifier_key` and `committed_index` are public.
///
/// `Index` is deliberately NOT exposed: wrappers constructed via
/// `with_keys(pk, vk)` never see the original `ix`, so an `index()` accessor
/// would be a lie for that construction path.
pub trait Preprocessed {
    type ProverKey;
    type VerifierKey: VerifierKeyCommitment;

    fn prover_key(&self) -> &Self::ProverKey;
    fn verifier_key(&self) -> &Self::VerifierKey;
    fn committed_index(&self) -> &CommittedIndexBytes;
}

/// Fixed tag for the canonical pair commitment of two verifier keys.
const VK_PAIR_TAG: &[u8] = b"argus:vk-pair:v1";

impl<V1, V2> VerifierKeyCommitment for (V1, V2)
where
    V1: VerifierKeyCommitment,
    V2: VerifierKeyCommitment,
{
    fn committed_index(&self) -> CommittedIndexBytes {
        let c1 = self.0.committed_index();
        let c1_enc = c1.encode();
        let c1_bytes = c1_enc.as_ref();
        let c2 = self.1.committed_index();
        let c2_enc = c2.encode();
        let c2_bytes = c2_enc.as_ref();

        let c1_len = u64::try_from(c1_bytes.len()).expect("commitment too large for u64 length");
        let c2_len = u64::try_from(c2_bytes.len()).expect("commitment too large for u64 length");

        let mut out =
            Vec::with_capacity(VK_PAIR_TAG.len() + 8 + c1_bytes.len() + 8 + c2_bytes.len());
        out.extend_from_slice(VK_PAIR_TAG);
        out.extend_from_slice(&c1_len.to_le_bytes());
        out.extend_from_slice(c1_bytes);
        out.extend_from_slice(&c2_len.to_le_bytes());
        out.extend_from_slice(c2_bytes);
        CommittedIndexBytes::new(out)
    }
}

// ---------------------------------------------------------------------------
// Indexed public input
// ---------------------------------------------------------------------------

/// Tag prefixed to the canonical encoding of an [`IndexedInstance`].
const INDEXED_INSTANCE_TAG: &[u8] = b"argus:indexed-instance:v1";

/// Public input for a prepared indexed protocol: the verifier-index commitment
/// paired with the per-claim instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedInstance<I> {
    committed_index: CommittedIndexBytes,
    instance: I,
}

impl<I> IndexedInstance<I> {
    pub fn new(committed_index: CommittedIndexBytes, instance: I) -> Self {
        Self {
            committed_index,
            instance,
        }
    }

    pub fn committed_index(&self) -> &CommittedIndexBytes {
        &self.committed_index
    }

    pub fn inner(&self) -> &I {
        &self.instance
    }

    pub fn into_inner(self) -> I {
        self.instance
    }
}

/// Borrowed counterpart to [`IndexedInstance`] for backends that want to
/// absorb the pair without forcing `Clone` on the instance type.
pub struct IndexedInstanceRef<'a, I> {
    committed_index: &'a CommittedIndexBytes,
    instance: &'a I,
}

impl<'a, I> IndexedInstanceRef<'a, I> {
    pub fn new(committed_index: &'a CommittedIndexBytes, instance: &'a I) -> Self {
        Self {
            committed_index,
            instance,
        }
    }

    pub fn committed_index(&self) -> &CommittedIndexBytes {
        self.committed_index
    }

    pub fn instance(&self) -> &I {
        self.instance
    }
}

fn encode_indexed_instance<I: Encoding<[u8]>>(
    committed_index: &CommittedIndexBytes,
    instance: &I,
) -> Vec<u8> {
    let committed_encoded = committed_index.encode();
    let committed_bytes = committed_encoded.as_ref();
    let instance_encoded = instance.encode();
    let instance_bytes = instance_encoded.as_ref();

    let instance_len =
        u64::try_from(instance_bytes.len()).expect("instance encoding too large for u64 length");

    let mut out = Vec::with_capacity(
        INDEXED_INSTANCE_TAG.len() + committed_bytes.len() + 8 + instance_bytes.len(),
    );
    out.extend_from_slice(INDEXED_INSTANCE_TAG);
    // committed_index is already length-delimited by its own encoding.
    out.extend_from_slice(committed_bytes);
    out.extend_from_slice(&instance_len.to_le_bytes());
    out.extend_from_slice(instance_bytes);
    out
}

impl<I: Encoding<[u8]>> Encoding<[u8]> for IndexedInstance<I> {
    fn encode(&self) -> impl AsRef<[u8]> {
        encode_indexed_instance(&self.committed_index, &self.instance)
    }
}

impl<I: Encoding<[u8]>> Encoding<[u8]> for IndexedInstanceRef<'_, I> {
    fn encode(&self) -> impl AsRef<[u8]> {
        encode_indexed_instance(self.committed_index, self.instance)
    }
}

// ---------------------------------------------------------------------------
// Keyed indexed authoring traits
// ---------------------------------------------------------------------------

/// Indexed (preprocessed) interactive argument.
///
/// Splits the relation into an [`Index`](Self::Index) and a per-claim
/// [`Instance`](Self::Instance) / [`Witness`](Self::Witness). The
/// [`index`](Self::index) function deterministically derives prover and
/// verifier keys; [`prove`](Self::prove) / [`verify`](Self::verify) execute
/// keyed.
///
/// There is no blanket implementation from [`InteractiveArgument`] into this
/// trait. Plain protocols stay plain. A protocol with real preprocessing
/// implements this trait directly. To use a plain protocol in the *inner* slot
/// of an indexed composition, wrap it in [`TrivialIndexedArgument`].
pub trait IndexedInteractiveArgument { // TODO: rename to PreprocessingInteractiveArgument
    type Index;
    type ProverKey;
    type VerifierKey: VerifierKeyCommitment; // TODO: add these keys to the indexed narg as well
    type Instance;
    type Witness;

    fn protocol_id(&self) -> impl AsRef<[u8]>;

    /// Deterministic indexer: derives the (prover key, verifier key) pair from
    /// the index `ix`.
    fn index(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey);

    fn prove<P: ProverChannel>(
        &self,
        ch: &mut P,
        pk: &Self::ProverKey,
        instance: &Self::Instance,
        witness: &Self::Witness,
    );

    fn verify<V: VerifierChannel>(
        &self,
        ch: &mut V,
        vk: &Self::VerifierKey,
        instance: &Self::Instance,
    ) -> VerificationResult<()>;
}

/// Indexed (preprocessed) interactive reduction.
///
/// Same split as [`IndexedInteractiveArgument`], with the standard reduction
/// shape: prove returns a target instance/witness pair; verify returns the
/// target instance.
pub trait IndexedInteractiveReduction { // TODO: rename to PreprocessingInteractiveReduction
    type Index;
    type ProverKey;
    type VerifierKey: VerifierKeyCommitment;
    type SourceInstance;
    type TargetInstance;
    type SourceWitness;
    type TargetWitness;

    fn protocol_id(&self) -> impl AsRef<[u8]>;

    fn index(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey);

    fn prove<P: ProverChannel>(
        &self,
        ch: &mut P,
        pk: &Self::ProverKey,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (Self::TargetInstance, Self::TargetWitness);

    fn verify<V: VerifierChannel>(
        &self,
        ch: &mut V,
        vk: &Self::VerifierKey,
        instance: &Self::SourceInstance,
    ) -> VerificationResult<Self::TargetInstance>;
}

// ---------------------------------------------------------------------------
// Prepared interactive adapters
// ---------------------------------------------------------------------------

/// Wraps an indexed argument plus its preprocessing keys as a plain
/// [`InteractiveArgument`] whose public input is an [`IndexedInstance`].
///
/// All fields are private; both constructors derive `committed_index` from
/// `vk.committed_index()` (Invariant 6). The IA impl checks that any
/// `IndexedInstance` it receives has a matching commitment: prover-side
/// mismatch panics (programmer error); verifier-side mismatch returns
/// [`VerificationError`].
pub struct PreparedArgument<B: IndexedInteractiveArgument> {
    body: B,
    pk: B::ProverKey,
    vk: B::VerifierKey,
    committed_index: CommittedIndexBytes,
}

impl<B: IndexedInteractiveArgument> PreparedArgument<B> {
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

impl<B: IndexedInteractiveArgument> Preprocessed for PreparedArgument<B> {
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

impl<B: IndexedInteractiveArgument> InteractiveArgument for PreparedArgument<B> {
    type Instance = IndexedInstance<B::Instance>;
    type Witness = B::Witness;

    fn protocol_id(&self) -> impl AsRef<[u8]> {
        self.body.protocol_id()
    }

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
pub struct PreparedReduction<B: IndexedInteractiveReduction> {
    body: B,
    pk: B::ProverKey,
    vk: B::VerifierKey,
    committed_index: CommittedIndexBytes,
}

impl<B: IndexedInteractiveReduction> PreparedReduction<B> {
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

impl<B: IndexedInteractiveReduction> Preprocessed for PreparedReduction<B> {
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

impl<B: IndexedInteractiveReduction> InteractiveReduction for PreparedReduction<B> {
    type SourceInstance = IndexedInstance<B::SourceInstance>;
    type TargetInstance = B::TargetInstance;
    type SourceWitness = B::SourceWitness;
    type TargetWitness = B::TargetWitness;

    fn protocol_id(&self) -> impl AsRef<[u8]> {
        self.body.protocol_id()
    }

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

// ---------------------------------------------------------------------------
// Trivial-index adapters
// ---------------------------------------------------------------------------

/// Wraps a plain [`InteractiveArgument`] as an [`IndexedInteractiveArgument`]
/// with unit index and unit keys (empty committed index).
///
/// Intended for the *inner* slot of a heterogeneous indexed composition so that
/// a plain protocol can sit beside a real indexed component. Wrapping a plain
/// protocol with this adapter and pushing it through prepared DSFS at the top
/// level will NOT produce the same bytes as the plain DSFS path — the prepared
/// transcript absorbs `IndexedInstance { committed_index: empty, instance: x }`
/// instead of the bare `x`. Use the plain DSFS path for top-level plain
/// protocols.
pub struct TrivialIndexedArgument<A>(pub A);

impl<A: InteractiveArgument> IndexedInteractiveArgument for TrivialIndexedArgument<A> {
    type Index = ();
    type ProverKey = ();
    type VerifierKey = ();
    type Instance = A::Instance;
    type Witness = A::Witness;

    fn protocol_id(&self) -> impl AsRef<[u8]> {
        self.0.protocol_id()
    }

    fn index(&self, _: &()) -> ((), ()) {
        ((), ())
    }

    fn prove<P: ProverChannel>(
        &self,
        ch: &mut P,
        _: &Self::ProverKey,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) {
        self.0.prove(ch, instance, witness)
    }

    fn verify<V: VerifierChannel>(
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

impl<R: InteractiveReduction> IndexedInteractiveReduction for TrivialIndexedReduction<R> {
    type Index = ();
    type ProverKey = ();
    type VerifierKey = ();
    type SourceInstance = R::SourceInstance;
    type TargetInstance = R::TargetInstance;
    type SourceWitness = R::SourceWitness;
    type TargetWitness = R::TargetWitness;

    fn protocol_id(&self) -> impl AsRef<[u8]> {
        self.0.protocol_id()
    }

    fn index(&self, _: &()) -> ((), ()) {
        ((), ())
    }

    fn prove<P: ProverChannel>(
        &self,
        ch: &mut P,
        _: &Self::ProverKey,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (Self::TargetInstance, Self::TargetWitness) {
        self.0.prove(ch, instance, witness)
    }

    fn verify<V: VerifierChannel>(
        &self,
        ch: &mut V,
        _: &Self::VerifierKey,
        instance: &Self::SourceInstance,
    ) -> VerificationResult<Self::TargetInstance> {
        self.0.verify(ch, instance)
    }
}

// ---------------------------------------------------------------------------
// Indexed composition (phase 4)
// ---------------------------------------------------------------------------

/// Composition tag for indexed `ChainedReduction`. Distinct from the plain
/// chained-reduction tag so that an indexed composition's `protocol_id` is
/// distinguishable from the plain one.
const INDEXED_CHAINED_REDUCTION_TAG: u8 = 0x03;

/// Composition tag for indexed `ReducedArgument`.
const INDEXED_REDUCED_ARGUMENT_TAG: u8 = 0x04;

impl<First, Second> IndexedInteractiveReduction for ChainedReduction<First, Second>
where
    First: IndexedInteractiveReduction,
    Second: IndexedInteractiveReduction<
            SourceInstance = First::TargetInstance,
            SourceWitness = First::TargetWitness,
        >,
{
    type Index = (First::Index, Second::Index);
    type ProverKey = (First::ProverKey, Second::ProverKey);
    type VerifierKey = (First::VerifierKey, Second::VerifierKey);
    type SourceInstance = First::SourceInstance;
    type TargetInstance = Second::TargetInstance;
    type SourceWitness = First::SourceWitness;
    type TargetWitness = Second::TargetWitness;

    fn protocol_id(&self) -> impl AsRef<[u8]> {
        derive_composition_id(
            INDEXED_CHAINED_REDUCTION_TAG,
            <First as IndexedInteractiveReduction>::protocol_id(&self.first).as_ref(),
            <Second as IndexedInteractiveReduction>::protocol_id(&self.second).as_ref(),
        )
    }

    fn index(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
        let (pk1, vk1) = self.first.index(&ix.0);
        let (pk2, vk2) = self.second.index(&ix.1);
        ((pk1, pk2), (vk1, vk2))
    }

    fn prove<P: ProverChannel>(
        &self,
        ch: &mut P,
        pk: &Self::ProverKey,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (Self::TargetInstance, Self::TargetWitness) {
        let (x2, w2) = self.first.prove(ch, &pk.0, instance, witness);
        self.second.prove(ch, &pk.1, &x2, &w2)
    }

    fn verify<V: VerifierChannel>(
        &self,
        ch: &mut V,
        vk: &Self::VerifierKey,
        instance: &Self::SourceInstance,
    ) -> VerificationResult<Self::TargetInstance> {
        let intermediate = self.first.verify(ch, &vk.0, instance)?;
        self.second.verify(ch, &vk.1, &intermediate)
    }
}

impl<R, A> IndexedInteractiveArgument for ReducedArgument<R, A>
where
    R: IndexedInteractiveReduction,
    A: IndexedInteractiveArgument<Instance = R::TargetInstance, Witness = R::TargetWitness>,
{
    type Index = (R::Index, A::Index);
    type ProverKey = (R::ProverKey, A::ProverKey);
    type VerifierKey = (R::VerifierKey, A::VerifierKey);
    type Instance = R::SourceInstance;
    type Witness = R::SourceWitness;

    fn protocol_id(&self) -> impl AsRef<[u8]> {
        derive_composition_id(
            INDEXED_REDUCED_ARGUMENT_TAG,
            <R as IndexedInteractiveReduction>::protocol_id(&self.reduction).as_ref(),
            <A as IndexedInteractiveArgument>::protocol_id(&self.argument).as_ref(),
        )
    }

    fn index(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
        let (pk1, vk1) = self.reduction.index(&ix.0);
        let (pk2, vk2) = self.argument.index(&ix.1);
        ((pk1, pk2), (vk1, vk2))
    }

    fn prove<P: ProverChannel>(
        &self,
        ch: &mut P,
        pk: &Self::ProverKey,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) {
        let (x2, w2) = self.reduction.prove(ch, &pk.0, instance, witness);
        self.argument.prove(ch, &pk.1, &x2, &w2);
    }

    fn verify<V: VerifierChannel>(
        &self,
        ch: &mut V,
        vk: &Self::VerifierKey,
        instance: &Self::Instance,
    ) -> VerificationResult<()> {
        let target_instance = self.reduction.verify(ch, &vk.0, instance)?;
        self.argument.verify(ch, &vk.1, &target_instance)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{pad_protocol_id, Decoding, Deserialize, NargSerialize};
    use alloc::vec;
    use alloc::vec::Vec;
    use core::cell::RefCell;

    // ---- Encoding tests ----

    #[test]
    fn committed_index_bytes_encoding_is_length_prefixed() {
        let cib = CommittedIndexBytes::new(vec![1, 2, 3]);
        let enc = cib.encode();
        let bytes = enc.as_ref();
        assert_eq!(&bytes[..8], &3u64.to_le_bytes());
        assert_eq!(&bytes[8..], &[1, 2, 3]);
    }

    #[test]
    fn unit_vk_has_empty_committed_index() {
        let cib: CommittedIndexBytes = ().committed_index();
        assert!(cib.is_empty());
        let enc = cib.encode();
        assert_eq!(enc.as_ref(), &0u64.to_le_bytes());
    }

    #[test]
    fn indexed_instance_encoding_changes_with_committed_index() {
        let ci_a = CommittedIndexBytes::new(vec![1, 2]);
        let ci_b = CommittedIndexBytes::new(vec![1, 2, 3]);
        let instance: u32 = 5;
        let a = IndexedInstance::new(ci_a, instance);
        let b = IndexedInstance::new(ci_b, instance);
        let a_enc = a.encode();
        let b_enc = b.encode();
        assert_ne!(a_enc.as_ref(), b_enc.as_ref());
    }

    #[test]
    fn indexed_instance_encoding_changes_with_instance() {
        let ci = CommittedIndexBytes::new(vec![1, 2]);
        let a = IndexedInstance::new(ci.clone(), 5u32);
        let b = IndexedInstance::new(ci, 6u32);
        assert_ne!(a.encode().as_ref(), b.encode().as_ref());
    }

    #[test]
    fn indexed_instance_ref_matches_owned_encoding() {
        let ci = CommittedIndexBytes::new(vec![9, 9]);
        let instance: u32 = 7;
        let owned = IndexedInstance::new(ci.clone(), instance);
        let by_ref = IndexedInstanceRef::new(&ci, &instance);
        assert_eq!(owned.encode().as_ref(), by_ref.encode().as_ref());
    }

    #[test]
    fn indexed_instance_encoding_starts_with_tag() {
        let ci = CommittedIndexBytes::new(vec![1]);
        let inst: u32 = 0;
        let ii = IndexedInstance::new(ci, inst);
        let bytes = ii.encode();
        assert!(bytes.as_ref().starts_with(INDEXED_INSTANCE_TAG));
    }

    // ---- Tuple VK commitment tests ----

    #[derive(Clone)]
    struct ByteVk(Vec<u8>);

    impl VerifierKeyCommitment for ByteVk {
        fn committed_index(&self) -> CommittedIndexBytes {
            CommittedIndexBytes::new(self.0.clone())
        }
    }

    #[test]
    fn tuple_vk_commitment_starts_with_pair_tag() {
        let pair = (ByteVk(vec![1, 2]), ByteVk(vec![3]));
        let commit = pair.committed_index();
        assert!(commit.as_bytes().starts_with(VK_PAIR_TAG));
    }

    #[test]
    fn tuple_vk_commitment_is_order_sensitive() {
        let a = (ByteVk(vec![1, 2]), ByteVk(vec![3])).committed_index();
        let b = (ByteVk(vec![3]), ByteVk(vec![1, 2])).committed_index();
        assert_ne!(a, b);
    }

    #[test]
    fn tuple_vk_commitment_distinguishes_split_points() {
        // (vec![1], vec![2, 3]) vs (vec![1, 2], vec![3]) must differ.
        let a = (ByteVk(vec![1]), ByteVk(vec![2, 3])).committed_index();
        let b = (ByteVk(vec![1, 2]), ByteVk(vec![3])).committed_index();
        assert_ne!(a, b);
    }

    // ---- Prepared adapter tests ----

    /// Minimal indexed argument:
    /// - Index = Vec<u8> (bytes go into the verifier-key commitment unchanged).
    /// - Prove sends one prover byte equal to the witness.
    /// - Verify accepts when that byte equals 0xAB.
    #[derive(Default)]
    struct DummyIndexedArg;

    #[derive(Clone)]
    struct DummyVerifierKey(Vec<u8>);

    impl VerifierKeyCommitment for DummyVerifierKey {
        fn committed_index(&self) -> CommittedIndexBytes {
            CommittedIndexBytes::new(self.0.clone())
        }
    }

    impl IndexedInteractiveArgument for DummyIndexedArg {
        type Index = Vec<u8>;
        type ProverKey = ();
        type VerifierKey = DummyVerifierKey;
        type Instance = ();
        // [u8; 1] gives us both NargSerialize and NargDeserialize for a single byte.
        type Witness = [u8; 1];

        fn protocol_id(&self) -> impl AsRef<[u8]> {
            pad_protocol_id(b"dummy-indexed-arg")
        }

        fn index(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
            ((), DummyVerifierKey(ix.clone()))
        }

        fn prove<P: ProverChannel>(
            &self,
            ch: &mut P,
            _: &Self::ProverKey,
            _: &Self::Instance,
            witness: &Self::Witness,
        ) {
            ch.send_prover_message(witness);
        }

        fn verify<V: VerifierChannel>(
            &self,
            ch: &mut V,
            _: &Self::VerifierKey,
            _: &Self::Instance,
        ) -> VerificationResult<()> {
            let m: [u8; 1] = ch.read_prover_message()?;
            if m[0] == 0xAB {
                Ok(())
            } else {
                Err(VerificationError)
            }
        }
    }

    /// Minimal in-memory channel pair for testing prepared adapters without DSFS.
    #[derive(Default)]
    struct RecordingProver {
        bytes: Vec<u8>,
    }

    impl ProverChannel for RecordingProver {
        fn send_prover_message<PM: Encoding<[u8]> + NargSerialize>(&mut self, msg: &PM) {
            msg.serialize_into_narg(&mut self.bytes);
        }
        fn read_verifier_message<VM: Decoding<[u8]>>(&mut self) -> VM {
            VM::decode(Default::default())
        }
    }

    struct ReplayingVerifier<'a> {
        cursor: &'a [u8],
    }

    impl VerifierChannel for ReplayingVerifier<'_> {
        fn read_prover_message<PM: Encoding<[u8]> + Deserialize>(
            &mut self,
        ) -> VerificationResult<PM> {
            PM::deserialize(&mut self.cursor)
        }
        fn send_verifier_message<VM: Decoding<[u8]>>(&mut self) -> VM {
            VM::decode(Default::default())
        }
    }

    #[test]
    fn prepared_argument_derives_committed_index_from_vk_via_prepare() {
        let ix = vec![7u8, 8, 9];
        let prepared = PreparedArgument::prepare(DummyIndexedArg, &ix);
        assert_eq!(prepared.committed_index().as_bytes(), &[7, 8, 9]);
    }

    #[test]
    fn prepared_argument_with_keys_derives_committed_index_from_vk() {
        let prepared =
            PreparedArgument::with_keys(DummyIndexedArg, (), DummyVerifierKey(vec![42]));
        assert_eq!(prepared.committed_index().as_bytes(), &[42]);
    }

    #[test]
    fn indexed_instance_helper_uses_stored_commitment() {
        let prepared = PreparedArgument::prepare(DummyIndexedArg, &vec![1u8, 2, 3]);
        let ii = prepared.indexed_instance(());
        assert_eq!(ii.committed_index().as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn prepared_argument_round_trip_via_in_memory_channel() {
        let prepared = PreparedArgument::prepare(DummyIndexedArg, &vec![1u8, 2, 3]);
        let ii = prepared.indexed_instance(());
        let mut p = RecordingProver::default();
        prepared.prove(&mut p, &ii, &[0xABu8]);
        let mut v = ReplayingVerifier { cursor: &p.bytes };
        assert!(prepared.verify(&mut v, &ii).is_ok());
    }

    #[test]
    #[should_panic(expected = "PreparedArgument::prove")]
    fn prepared_argument_prove_panics_on_commitment_mismatch() {
        let prepared = PreparedArgument::prepare(DummyIndexedArg, &vec![1u8, 2, 3]);
        let mismatched = IndexedInstance::new(CommittedIndexBytes::new(vec![9, 9]), ());
        let mut p = RecordingProver::default();
        prepared.prove(&mut p, &mismatched, &[0xABu8]);
    }

    #[test]
    fn prepared_argument_verify_rejects_on_commitment_mismatch() {
        let prepared = PreparedArgument::prepare(DummyIndexedArg, &vec![1u8, 2, 3]);
        let mismatched = IndexedInstance::new(CommittedIndexBytes::new(vec![9, 9]), ());
        let mut v = ReplayingVerifier { cursor: &[] };
        assert!(prepared.verify(&mut v, &mismatched).is_err());
    }

    // ---- Trivial-index adapter ----

    #[derive(Default)]
    struct PlainOk;

    impl InteractiveArgument for PlainOk {
        type Instance = ();
        type Witness = ();
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            pad_protocol_id(b"plain-ok")
        }
        fn prove<P: ProverChannel>(&self, _: &mut P, _: &(), _: &()) {}
        fn verify<V: VerifierChannel>(&self, _: &mut V, _: &()) -> VerificationResult<()> {
            Ok(())
        }
    }

    #[test]
    fn trivial_indexed_argument_has_empty_committed_index() {
        let wrapped = TrivialIndexedArgument(PlainOk);
        let (_, vk) = wrapped.index(&());
        assert!(vk.committed_index().is_empty());
    }

    // ---- Indexed composition tests ----

    /// Indexed reduction: source instance is a `u8`, target is the same byte
    /// plus the prover-key value. The verifier key carries an opaque byte that
    /// is exposed as the committed index.
    struct AddPk;

    #[derive(Clone)]
    struct AddPkVk(u8);

    impl VerifierKeyCommitment for AddPkVk {
        fn committed_index(&self) -> CommittedIndexBytes {
            CommittedIndexBytes::new(vec![self.0])
        }
    }

    impl IndexedInteractiveReduction for AddPk {
        type Index = u8;
        type ProverKey = u8;
        type VerifierKey = AddPkVk;
        type SourceInstance = u8;
        type TargetInstance = u8;
        type SourceWitness = ();
        type TargetWitness = ();

        fn protocol_id(&self) -> impl AsRef<[u8]> {
            pad_protocol_id(b"add-pk")
        }

        fn index(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
            (*ix, AddPkVk(*ix))
        }

        fn prove<P: ProverChannel>(
            &self,
            _: &mut P,
            pk: &Self::ProverKey,
            instance: &Self::SourceInstance,
            _: &Self::SourceWitness,
        ) -> (Self::TargetInstance, Self::TargetWitness) {
            (instance.wrapping_add(*pk), ())
        }

        fn verify<V: VerifierChannel>(
            &self,
            _: &mut V,
            vk: &Self::VerifierKey,
            instance: &Self::SourceInstance,
        ) -> VerificationResult<Self::TargetInstance> {
            Ok(instance.wrapping_add(vk.0))
        }
    }

    /// Indexed argument that succeeds iff the per-claim instance equals the
    /// verifier-key byte.
    struct EqualsKey;

    #[derive(Clone)]
    struct EqualsKeyVk(u8);

    impl VerifierKeyCommitment for EqualsKeyVk {
        fn committed_index(&self) -> CommittedIndexBytes {
            CommittedIndexBytes::new(vec![self.0])
        }
    }

    impl IndexedInteractiveArgument for EqualsKey {
        type Index = u8;
        type ProverKey = ();
        type VerifierKey = EqualsKeyVk;
        type Instance = u8;
        type Witness = ();

        fn protocol_id(&self) -> impl AsRef<[u8]> {
            pad_protocol_id(b"equals-key")
        }

        fn index(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
            ((), EqualsKeyVk(*ix))
        }

        fn prove<P: ProverChannel>(
            &self,
            _: &mut P,
            _: &Self::ProverKey,
            _: &Self::Instance,
            _: &Self::Witness,
        ) {
        }

        fn verify<V: VerifierChannel>(
            &self,
            _: &mut V,
            vk: &Self::VerifierKey,
            instance: &Self::Instance,
        ) -> VerificationResult<()> {
            if *instance == vk.0 {
                Ok(())
            } else {
                Err(VerificationError)
            }
        }
    }

    #[test]
    fn indexed_chained_reduction_routes_per_step_keys() {
        let composed = ChainedReduction::new(AddPk, AddPk);
        // index pair: first adds 3, second adds 4.
        let ix = (3u8, 4u8);
        let (pk, vk) = composed.index(&ix);
        assert_eq!(pk, (3, 4));
        // Composed VK commitment must be canonical pair (just check that it
        // exists and starts with the pair tag).
        assert!(vk.committed_index().as_bytes().starts_with(VK_PAIR_TAG));

        // Prove and verify a small input.
        let recorder = RefCell::new(Vec::new());
        let mut p = NullProverChannel(&recorder);
        let (target, ()) = composed.prove(&mut p, &pk, &10u8, &());
        assert_eq!(target, 17);

        let mut v = NullVerifierChannel;
        let target_v = composed.verify(&mut v, &vk, &10u8).unwrap();
        assert_eq!(target_v, 17);
    }

    #[test]
    fn indexed_reduced_argument_executes_through_indexed_pair() {
        let composed = ReducedArgument::new(AddPk, EqualsKey);
        let ix = (5u8, 17u8);
        let (pk, vk) = composed.index(&ix);
        assert_eq!(pk, (5, ()));

        // Source instance 12, plus pk=5, equals 17, which matches argument vk.
        let recorder = RefCell::new(Vec::new());
        let mut p = NullProverChannel(&recorder);
        composed.prove(&mut p, &pk, &12u8, &());

        let mut v = NullVerifierChannel;
        assert!(composed.verify(&mut v, &vk, &12u8).is_ok());

        // Wrong source instance should fail at the argument's vk check.
        let mut v2 = NullVerifierChannel;
        assert!(composed.verify(&mut v2, &vk, &11u8).is_err());
    }

    // Channels for composition tests: AddPk and EqualsKey don't read/write the
    // channel, so a trivial pair is enough.
    struct NullProverChannel<'a>(&'a RefCell<Vec<u8>>);
    impl ProverChannel for NullProverChannel<'_> {
        fn send_prover_message<PM: Encoding<[u8]> + NargSerialize>(&mut self, msg: &PM) {
            msg.serialize_into_narg(&mut self.0.borrow_mut());
        }
        fn read_verifier_message<VM: Decoding<[u8]>>(&mut self) -> VM {
            VM::decode(Default::default())
        }
    }

    struct NullVerifierChannel;
    impl VerifierChannel for NullVerifierChannel {
        fn read_prover_message<PM: Encoding<[u8]> + Deserialize>(
            &mut self,
        ) -> VerificationResult<PM> {
            Err(VerificationError)
        }
        fn send_verifier_message<VM: Decoding<[u8]>>(&mut self) -> VM {
            VM::decode(Default::default())
        }
    }
}
