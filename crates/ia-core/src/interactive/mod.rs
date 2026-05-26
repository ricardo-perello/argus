//! Interactive protocol traits, adapters, and composition.

mod adapters;
mod argument;
mod composition;
mod macros;
mod preprocessing;
mod reduction;

pub use adapters::{
    PreparedArgument, PreparedReduction, TrivialIndexedArgument, TrivialIndexedReduction,
};
pub use argument::InteractiveArgument;
pub use composition::{ChainedReduction, ReducedArgument};
pub use preprocessing::{PreprocessingInteractiveArgument, PreprocessingInteractiveReduction};
pub use reduction::InteractiveReduction;
