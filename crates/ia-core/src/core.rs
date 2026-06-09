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
    ///
    /// Implementations must ensure that keys returned from the same index bind
    /// the same committed index:
    ///
    /// ```text
    /// prover_key.committed_index() == verifier_key.committed_index()
    /// ```
    ///
    /// DSFS binds the prover-key commitment on the proving path and the
    /// verifier-key commitment on the verification path. Violating this
    /// contract makes the two transcripts diverge, so proofs fail to verify.
    fn preprocess(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey);
}
