//! Shared protocol core traits.
//!
//! These traits provide the inheritance spine for Argus protocol authoring:
//! protocol identity at the root, argument/reduction shape metadata in the
//! middle, and executable interactive traits as leaf capabilities.

use crate::indexed::VerifierKeyCommitment;

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
    /// Prover-side key derived from the index.
    type ProverKey;
    /// Verifier-side key derived from the index.
    type VerifierKey: VerifierKeyCommitment;

    /// Deterministic indexer: derives `(prover_key, verifier_key)` from `ix`.
    fn index(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey);
}
