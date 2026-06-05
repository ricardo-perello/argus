//! Non-interactive protocol abstractions.
//!
//! The IA traits model public-coin protocols as channel programs. The traits in
//! this module model the result after a compiler such as DSFS has removed the
//! verifier's live randomness and produced a single non-interactive artifact.
//!
//! `ia-core` owns these types because they are abstract protocol vocabulary:
//! they say what a non-interactive argument or reduction is, but they do not
//! specify Fiat-Shamir, duplex sponges, domain separation, or any concrete proof
//! layout. Concrete compilers live outside this crate and implement these traits.

mod adapters;
mod argument;
mod preprocessing;
mod proof;
mod reduction;
mod session;

pub use adapters::NargAsInteractiveArgument;
pub use argument::{
    NonInteractiveArgument, NonInteractiveArgumentProver, NonInteractiveArgumentVerifier,
};
pub use preprocessing::{
    PreprocessingNonInteractiveArgument, PreprocessingNonInteractiveArgumentProver,
    PreprocessingNonInteractiveArgumentVerifier, PreprocessingNonInteractiveReduction,
    PreprocessingNonInteractiveReductionProver, PreprocessingNonInteractiveReductionVerifier,
};
pub use proof::NargProof;
pub use reduction::{
    NonInteractiveReduction, NonInteractiveReductionProver, NonInteractiveReductionVerifier,
};
pub use session::NonInteractiveSession;
