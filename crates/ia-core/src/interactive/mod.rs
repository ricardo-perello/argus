//! Interactive protocol traits, adapters, and composition.

mod adapters;
mod argument;
mod composition;
mod macros;
mod preprocessing;
mod reduction;

pub use adapters::{
    TrivialIndexedArgumentProver, TrivialIndexedArgumentVerifier, TrivialIndexedReductionProver,
    TrivialIndexedReductionVerifier, TrivialIndexer,
};
pub use argument::{InteractiveArgumentProver, InteractiveArgumentVerifier};
pub use composition::{ChainedReduction, ReducedArgument};
pub use preprocessing::{
    PreprocessingInteractiveArgumentProver, PreprocessingInteractiveArgumentVerifier,
    PreprocessingInteractiveReductionProver, PreprocessingInteractiveReductionVerifier,
};
pub use reduction::{InteractiveReductionProver, InteractiveReductionVerifier};
