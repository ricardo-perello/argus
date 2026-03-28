//! Core abstractions for public-coin interactive arguments and reductions.
//!
//! Defines channel traits, the `InteractiveArgument` interface, and the
//! `InteractiveReduction` interface.
//!
//! Codec traits (`Encoding`, `Decoding`) are re-exported from spongefish.
//! `Deserialize` is defined in [`deserialize`] with a blanket impl from
//! `spongefish::NargDeserialize`.
//!
//! Submodules: [`error`], [`security`], [`deserialize`], [`channel`],
//! [`argument`], [`reduction`], [`compose`].
#![no_std]
extern crate alloc;

mod argument;
mod channel;
mod compose;
mod deserialize;
mod error;
mod reduction;
mod security;

pub use spongefish::{Decoding, Encoding};

pub use argument::{InteractiveArgument, Prove, Verify};
pub use channel::{ProverChannel, VerifierChannel};
pub use compose::{ChainedReduction, ReducedArgument};
pub use deserialize::Deserialize;
pub use error::{VerificationError, VerificationResult};
pub use reduction::{InteractiveReduction, ReduceProve, ReduceVerify};
pub use security::{SecurityErrorBound, SecurityProfile};
