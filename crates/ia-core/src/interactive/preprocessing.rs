//! Preprocessing interactive protocol traits and preprocessing composition.

use crate::{
    ArgumentCore, PreprocessingCore, ProverChannel, ReductionCore, VerificationResult,
    VerifierChannel,
};

/// Indexed (preprocessed) interactive argument.
///
/// Splits the relation into an index and a per-claim instance/witness pair.
/// The `PreprocessingCore::index` function deterministically derives prover and
/// verifier keys; [`prove`](Self::prove) / [`verify`](Self::verify) execute
/// keyed.
///
/// There is no blanket implementation from [`crate::InteractiveArgument`] into this
/// trait. Plain protocols stay plain. A protocol with real preprocessing
/// implements this trait directly. To use a plain protocol in the *inner* slot
/// of a preprocessing composition, wrap it in [`crate::TrivialIndexedArgument`].
pub trait PreprocessingInteractiveArgument: ArgumentCore + PreprocessingCore {
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
/// Same split as [`PreprocessingInteractiveArgument`], with the standard reduction
/// shape: prove returns a target instance/witness pair; verify returns the
/// target instance.
pub trait PreprocessingInteractiveReduction: ReductionCore + PreprocessingCore {
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ChainedReduction;
    use crate::preprocessing::{INDEXED_INSTANCE_TAG, VK_PAIR_TAG};
    use crate::{
        CommittedIndexBytes, Decoding, Deserialize, Encoding, IndexedInstance, IndexedInstanceRef,
        InteractiveArgument, NargSerialize, ProtocolCore, ReducedArgument, TrivialIndexedArgument,
        VerificationError, VerifierKeyCommitment, pad_protocol_id,
    };
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

    // ---- Trivial-index adapter ----

    #[derive(Default)]
    struct PlainOk;

    impl ProtocolCore for PlainOk {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            pad_protocol_id(b"plain-ok")
        }
    }

    impl ArgumentCore for PlainOk {
        type Instance = ();
        type Witness = ();
    }

    impl InteractiveArgument for PlainOk {
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

    // ---- Preprocessing composition tests ----

    /// Preprocessing reduction: source instance is a `u8`, target is the same byte
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

    impl ProtocolCore for AddPk {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            pad_protocol_id(b"add-pk")
        }
    }

    impl ReductionCore for AddPk {
        type SourceInstance = u8;
        type TargetInstance = u8;
        type SourceWitness = ();
        type TargetWitness = ();
    }

    impl PreprocessingCore for AddPk {
        type Index = u8;
        type ProverKey = u8;
        type VerifierKey = AddPkVk;

        fn index(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
            (*ix, AddPkVk(*ix))
        }
    }

    impl PreprocessingInteractiveReduction for AddPk {
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

    /// Preprocessing argument that succeeds iff the per-claim instance equals the
    /// verifier-key byte.
    struct EqualsKey;

    #[derive(Clone)]
    struct EqualsKeyVk(u8);

    impl VerifierKeyCommitment for EqualsKeyVk {
        fn committed_index(&self) -> CommittedIndexBytes {
            CommittedIndexBytes::new(vec![self.0])
        }
    }

    impl ProtocolCore for EqualsKey {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            pad_protocol_id(b"equals-key")
        }
    }

    impl ArgumentCore for EqualsKey {
        type Instance = u8;
        type Witness = ();
    }

    impl PreprocessingCore for EqualsKey {
        type Index = u8;
        type ProverKey = ();
        type VerifierKey = EqualsKeyVk;

        fn index(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
            ((), EqualsKeyVk(*ix))
        }
    }

    impl PreprocessingInteractiveArgument for EqualsKey {
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
