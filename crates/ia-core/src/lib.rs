//! Core abstractions for public-coin interactive arguments and reductions.
//!
//! Defines channel traits, the core protocol hierarchy, preprocessing support,
//! composition, non-interactive vocabulary, and security metadata. Codec traits
//! (`Encoding`, `Decoding`, `NargSerialize`, `NargDeserialize`, `Deserialize`)
//! and the verification error type live in `spongefish` and are re-exported here
//! for protocol implementors.
//!
//! The public re-exports are intentionally flat: protocol authors can import
//! `InteractiveArgument`, `PreprocessingInteractiveArgument`, `ProtocolCore`,
//! `ArgumentCore`, and the channel traits directly from `ia_core`.
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
/// Convenience for implementing `InteractiveArgument::protocol_id()` with a
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
pub use core::{ArgumentCore, PreprocessingCore, ProtocolCore, ReductionCore};
pub use interactive::{
    ChainedReduction, InteractiveArgument, InteractiveReduction, PreprocessingInteractiveArgument,
    PreprocessingInteractiveReduction, ReducedArgument, TrivialIndexedArgument,
    TrivialIndexedReduction,
};
pub use noninteractive::{
    NargAsInteractiveArgument, NargProof, NonInteractiveArgument, NonInteractiveReduction,
    PreprocessingNonInteractiveArgument, PreprocessingNonInteractiveReduction, Prover,
    ProverReduction, Verifier, VerifierReduction,
};
pub use preprocessing::{
    CommittedIndexBytes, IndexedInstance, IndexedInstanceRef, ProvingKey, VerifierKeyCommitment,
};
pub use security::{
    ArgumentSecurity, PreprocessingArgumentSecurity, PreprocessingReductionSecurity,
    ReductionSecurity, SecurityErrorBound, SecurityProfile,
};
