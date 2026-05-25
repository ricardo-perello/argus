//! Interactive protocol traits, adapters, and composition.

mod argument;
mod composition;
mod prepared;
mod preprocessing;
mod reduction;
mod trivial;

pub use argument::InteractiveArgument;
pub use composition::{ChainedReduction, ReducedArgument};
pub use prepared::{PreparedArgument, PreparedReduction};
pub use preprocessing::{PreprocessingInteractiveArgument, PreprocessingInteractiveReduction};
pub use reduction::InteractiveReduction;
pub use trivial::{TrivialIndexedArgument, TrivialIndexedReduction};
