//! Core abstractions for public-coin interactive arguments and reductions.
//!
//! Defines channel traits, the `InteractiveArgument` interface, and the
//! `InteractiveReduction` interface.
//!
//! Codec traits (`Encoding`, `Decoding`, `NargSerialize`, `NargDeserialize`)
//! live here so the IA/NARG abstraction is independent of any sponge backend.
//!
//! Submodules: [`error`], [`security`], [`io`], [`codecs`], [`deserialize`],
//! [`channel`], [`argument`], [`reduction`], [`narg`], [`compose`].
#![no_std]
extern crate alloc;

mod argument;
mod channel;
mod codecs;
mod compose;
mod deserialize;
#[cfg(any(feature = "ark-ec", feature = "ark-ff", feature = "curve25519-dalek"))]
mod drivers;
mod error;
mod io;
mod narg;
mod reduction;
mod security;

pub use codecs::{ByteArray, Codec, Decoding, Encoding};
pub use io::{NargDeserialize, NargSerialize};

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
pub use deserialize::Deserialize;
pub use error::{VerificationError, VerificationResult};
pub use narg::{
    NargAsInteractiveArgument, NargProof, NonInteractiveArgument, NonInteractiveReduction,
};
pub use reduction::InteractiveReduction;
pub use security::{CodeSecurityParams, ProtocolSecurity, SecurityErrorBound, SecurityProfile};
