//! Core abstractions for public-coin interactive arguments and reductions.
//!
//! Defines channel traits, the `InteractiveArgument` interface, and the
//! `InteractiveReduction` interface. Codec traits (`Encoding`, `Decoding`,
//! `NargSerialize`, `NargDeserialize`, `Deserialize`) and the verification error
//! type live in `spongefish` and are re-exported here for protocol implementors.
//!
//! Submodules: [`security`], [`channel`], [`argument`], [`reduction`], [`narg`],
//! [`compose`].
#![no_std]
extern crate alloc;

mod argument;
mod channel;
mod compose;
mod indexed;
mod indexed_security;
mod narg;
mod reduction;
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

pub use argument::InteractiveArgument;
pub use channel::{ProverChannel, VerifierChannel};
pub use compose::{ChainedReduction, ReducedArgument};
pub use indexed::{
    CommittedIndexBytes, IndexedInstance, IndexedInstanceRef, IndexedInteractiveArgument,
    IndexedInteractiveReduction, PreparedArgument, PreparedReduction, Preprocessed,
    TrivialIndexedArgument, TrivialIndexedReduction, VerifierKeyCommitment,
};
pub use indexed_security::{IndexedArgumentSecurity, IndexedReductionSecurity};
pub use narg::{
    IndexedNonInteractiveArgument, IndexedNonInteractiveReduction, NargAsInteractiveArgument,
    NargProof, NonInteractiveArgument, NonInteractiveReduction,
};
pub use reduction::InteractiveReduction;
pub use security::{
    ArgumentSecurity, ReductionSecurity, SecurityErrorBound, SecurityProfile,
};
