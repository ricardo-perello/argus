//! Interactive protocol traits, adapters, and composition.

mod adapters;
mod argument;
mod composition;
mod macros;
mod preprocessing;
mod reduction;

pub use adapters::{
    CombinedIA, IntoProver, IntoVerifier, ProverOnly, TrivialIndexedArgument,
    TrivialIndexedReduction, VerifierOnly,
};
pub use argument::{InteractiveArgument, InteractiveArgumentProver, InteractiveArgumentVerifier};
pub use composition::{ChainedReduction, ReducedArgument};
pub use preprocessing::{
    PreprocessingInteractiveArgument, PreprocessingInteractiveArgumentProver,
    PreprocessingInteractiveArgumentVerifier, PreprocessingInteractiveReduction,
    PreprocessingInteractiveReductionProver, PreprocessingInteractiveReductionVerifier,
};
pub use reduction::{
    InteractiveReduction, InteractiveReductionProver, InteractiveReductionVerifier,
};
