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
///
/// A verifier role does not acquire the prover's witness type:
///
/// ```compile_fail
/// use ia_core::{
///     ArgumentCore, ArgumentProverCore, InteractiveArgumentVerifier, ProtocolCore,
///     VerificationResult, VerifierChannel,
/// };
///
/// struct Verifier;
/// impl ProtocolCore for Verifier {
///     fn protocol_id(&self) -> impl AsRef<[u8]> { b"verifier" }
/// }
/// impl ArgumentCore for Verifier { type Instance = (); }
/// impl InteractiveArgumentVerifier for Verifier {
///     fn verify<C: VerifierChannel<Unit = u8>>(
///         &self,
///         _: &mut C,
///         _: &Self::Instance,
///     ) -> VerificationResult<()> { Ok(()) }
/// }
///
/// fn requires_witness<T: ArgumentProverCore>() {}
/// requires_witness::<Verifier>();
/// ```
pub trait ArgumentCore: ProtocolCore {
    /// Public statement.
    type Instance;
}

/// Prover-only shape metadata for arguments.
pub trait ArgumentProverCore: ArgumentCore {
    /// Prover's private input.
    type Witness;
}

/// Shared shape metadata for protocol cores whose verifier outputs a target.
pub trait ReductionCore: ProtocolCore {
    /// Input instance (the claim being reduced).
    type SourceInstance;
    /// Output instance (the reduced claim the verifier computes).
    type TargetInstance;
}

/// Prover-only shape metadata for reductions.
pub trait ReductionProverCore: ReductionCore {
    /// Prover's private input for the source relation.
    type SourceWitness;
    /// Prover's output: private input for the target relation.
    type TargetWitness;
}

/// Independent preprocessing role.
///
/// Implementing indexing does not grant either executable role:
///
/// ```compile_fail
/// use ia_core::{
///     ArgumentCore, Indexer, PreprocessingInteractiveArgumentVerifier, ProtocolCore,
/// };
///
/// struct IndexerOnly;
/// impl ProtocolCore for IndexerOnly {
///     fn protocol_id(&self) -> impl AsRef<[u8]> { b"indexer" }
/// }
/// impl ArgumentCore for IndexerOnly { type Instance = (); }
/// impl Indexer for IndexerOnly {
///     type Index = ();
///     type ProverKey = ();
///     type VerifierKey = ();
///     fn preprocess(&self, _: &()) -> ((), ()) { ((), ()) }
/// }
///
/// fn requires_verifier<T: PreprocessingInteractiveArgumentVerifier>() {}
/// requires_verifier::<IndexerOnly>();
/// ```
pub trait Indexer: ProtocolCore {
    /// Static problem description that is preprocessed once.
    type Index;
    /// Prover-side key derived from the index. Carries (or can recompute) the
    /// committed index so the prover binds it without ever holding `vk`.
    type ProverKey: CommittedIndex;
    /// Verifier-side key derived from the index.
    type VerifierKey: CommittedIndex;

    /// Deterministic indexer: derives `(prover_key, verifier_key)` from `ix`.
    fn preprocess(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey);

    /// Run [`preprocess`](Self::preprocess), then check that the two keys agree
    /// on the committed index.
    ///
    /// The compiled prover binds `pk.committed_index()` and the verifier binds
    /// `vk.committed_index()` (see [`CommittedIndex`]). If the author's two impls
    /// disagree for keys from the same `ix`, the prover and verifier transcripts
    /// diverge and *every* proof fails to verify. This guard surfaces that author
    /// error at preprocessing time, where both keys are in hand, instead of as an
    /// opaque verification failure later. Deployment code should distribute keys
    /// only after this method succeeds.
    fn preprocess_checked(
        &self,
        ix: &Self::Index,
    ) -> Result<(Self::ProverKey, Self::VerifierKey), IndexingError> {
        let (pk, vk) = self.preprocess(ix);
        if pk.committed_index() != vk.committed_index() {
            return Err(IndexingError::CommittedIndexMismatch);
        }
        Ok((pk, vk))
    }
}

/// Errors detected while deriving prover and verifier keys from an index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexingError {
    /// The two keys would bind different committed indices into their transcripts.
    CommittedIndexMismatch,
}
