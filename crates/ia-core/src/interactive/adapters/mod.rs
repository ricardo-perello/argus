//! Interactive adapters between plain and preprocessing protocol surfaces.

mod plain_to_preprocessing;
mod preprocessing_to_plain;

pub use plain_to_preprocessing::{TrivialIndexedArgument, TrivialIndexedReduction};
pub use preprocessing_to_plain::{PreparedArgument, PreparedReduction};
