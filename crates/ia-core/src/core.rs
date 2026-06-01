//! Shared protocol core traits.
//!
//! These traits provide the inheritance spine for Argus protocol authoring:
//! protocol identity at the root, argument/reduction shape metadata in the
//! middle, and executable interactive traits as leaf capabilities.

use crate::CommittedIndex;

/// Common identity for any protocol core.
pub trait ProtocolCore {
    /// Variable-length protocol identifier for domain separation.
    ///
    /// May depend on runtime structure of the protocol instance (e.g. a
    /// composition tree). The DSFS backend compacts and mixes this with a
    /// sponge tag and session to form the full domain separator. Leaf
    /// protocols may return a fixed `[u8; 32]` (via [`crate::pad_protocol_id`])
    /// or a short byte slice.
    fn protocol_id(&self) -> impl AsRef<[u8]>;
}

/// Shared shape metadata for protocol cores whose verifier accepts/rejects.
pub trait ArgumentCore: ProtocolCore {
    /// Public statement.
    type Instance;
    /// Prover's private input.
    type Witness;
}

/// Shared shape metadata for protocol cores whose verifier outputs a target.
pub trait ReductionCore: ProtocolCore {
    /// Input instance (the claim being reduced).
    type SourceInstance;
    /// Output instance (the reduced claim the verifier computes).
    type TargetInstance;
    /// Prover's private input for the source relation.
    type SourceWitness;
    /// Prover's output: private input for the target relation.
    type TargetWitness;
}

/// Shared preprocessing metadata for protocol cores with preprocessing.
pub trait PreprocessingCore: ProtocolCore {
    /// Static problem description that is preprocessed once.
    type Index;
    /// Prover-side key derived from the index. Carries (or can recompute) the
    /// committed index so the prover binds it without ever holding `vk`.
    type ProverKey: CommittedIndex;
    /// Verifier-side key derived from the index.
    type VerifierKey: CommittedIndex;

    /// Deterministic indexer: derives `(prover_key, verifier_key)` from `ix`.
    fn preprocess(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey);

    /// Run [`preprocess`](Self::preprocess), then assert the two keys agree on
    /// the committed index.
    ///
    /// The compiled prover binds `pk.committed_index()` and the verifier binds
    /// `vk.committed_index()` (see [`CommittedIndex`]). If the author's two impls
    /// disagree for keys from the same `ix`, the prover and verifier transcripts
    /// diverge and *every* proof fails to verify. This guard surfaces that author
    /// error at preprocessing time — where both keys are in hand — instead of as
    /// an opaque verification failure later. Backends run preprocessing through
    /// this method, so the check fires on the compiled path without any extra
    /// call-site work.
    fn preprocess_checked(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
        let (pk, vk) = self.preprocess(ix);
        debug_assert_eq!(
            pk.committed_index(),
            vk.committed_index(),
            "PreprocessingCore::preprocess returned prover/verifier keys with mismatched \
             committed_index; the prover and verifier transcripts would diverge",
        );
        (pk, vk)
    }
}
