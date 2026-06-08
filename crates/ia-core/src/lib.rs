//! Core abstractions for public-coin interactive arguments and reductions.
//!
//! Defines channel traits, the core protocol hierarchy, preprocessing support,
//! composition, non-interactive vocabulary, and security metadata. Codec traits
//! (`Encoding`, `Decoding`, `NargSerialize`, `NargDeserialize`, `Deserialize`)
//! and the verification error type live in `spongefish` and are re-exported here
//! for protocol implementors.
//!
//! The public re-exports are intentionally flat: protocol authors can import
//! the prover, verifier, and indexer role traits directly from `ia_core`.
#![no_std]
extern crate alloc;

mod channel;
mod core;
mod interactive;
mod noninteractive;
mod preprocessing;
mod security;

pub use spongefish::{
    ByteArray, Codec, Decoding, Deserialize, Encoding, NargDeserialize, NargSerialize,
    VerificationError, VerificationResult,
};

/// Zero-pad a byte slice into a 32-byte protocol identifier.
///
/// Convenience for implementing [`ProtocolCore::protocol_id`] with a
/// short human-readable ASCII label, following the sigma-proofs convention.
/// Panics at compile time if `label` is longer than 32 bytes.
pub const fn pad_protocol_id(label: &[u8]) -> [u8; 32] {
    assert!(label.len() <= 32, "protocol id label must be <= 32 bytes");
    let mut id = [0u8; 32];
    let mut i = 0;
    while i < label.len() {
        id[i] = label[i];
        i += 1;
    }
    id
}

pub use channel::{ProverChannel, VerifierChannel};
pub use core::{
    ArgumentCore, ArgumentProverCore, Indexer, IndexingError, ProtocolCore, ReductionCore,
    ReductionProverCore,
};
pub use interactive::{
    ChainedReduction, InteractiveArgumentProver, InteractiveArgumentVerifier,
    InteractiveReductionProver, InteractiveReductionVerifier,
    PreprocessingInteractiveArgumentProver, PreprocessingInteractiveArgumentVerifier,
    PreprocessingInteractiveReductionProver, PreprocessingInteractiveReductionVerifier,
    ReducedArgument, TrivialIndexedArgumentProver, TrivialIndexedArgumentVerifier,
    TrivialIndexedReductionProver, TrivialIndexedReductionVerifier, TrivialIndexer,
};
pub use noninteractive::{
    NargProof, NargProverAsInteractiveArgument, NargVerifierAsInteractiveArgument,
    NonInteractiveArgumentProver, NonInteractiveArgumentVerifier, NonInteractiveReductionProver,
    NonInteractiveReductionVerifier, NonInteractiveSession,
    PreprocessingNonInteractiveArgumentProver, PreprocessingNonInteractiveArgumentVerifier,
    PreprocessingNonInteractiveReductionProver, PreprocessingNonInteractiveReductionVerifier,
};
pub use preprocessing::{CommittedIndex, CommittedIndexBytes, IndexedInstance, IndexedInstanceRef};
pub use security::{
    ArgumentSecurity, PreprocessingArgumentSecurity, PreprocessingReductionSecurity,
    ReductionSecurity, SecurityErrorBound, SecurityProfile,
};

/// Common execution traits for authoring and running protocols.
///
/// Calling `.prove()` / `.verify()` needs the relevant native role trait in
/// scope. Glob-importing this prelude brings every executable role plus the
/// public/prover core, indexer, session, and channel traits into scope.
pub mod prelude {
    pub use crate::{
        ArgumentCore, ArgumentProverCore, Indexer, InteractiveArgumentProver,
        InteractiveArgumentVerifier, InteractiveReductionProver, InteractiveReductionVerifier,
        NonInteractiveArgumentProver, NonInteractiveArgumentVerifier,
        NonInteractiveReductionProver, NonInteractiveReductionVerifier, NonInteractiveSession,
        PreprocessingInteractiveArgumentProver, PreprocessingInteractiveArgumentVerifier,
        PreprocessingInteractiveReductionProver, PreprocessingInteractiveReductionVerifier,
        PreprocessingNonInteractiveArgumentProver, PreprocessingNonInteractiveArgumentVerifier,
        PreprocessingNonInteractiveReductionProver, PreprocessingNonInteractiveReductionVerifier,
        ProtocolCore, ProverChannel, ReductionCore, ReductionProverCore, VerifierChannel,
    };
}
