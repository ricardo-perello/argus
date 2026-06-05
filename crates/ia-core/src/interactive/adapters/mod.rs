//! Interactive adapters between plain and preprocessing protocol surfaces.

mod combined_ia;
mod plain_to_preprocessing;
mod role_views;

pub use combined_ia::CombinedIA;
pub use plain_to_preprocessing::{TrivialIndexedArgument, TrivialIndexedReduction};
pub use role_views::{IntoProver, IntoVerifier, ProverOnly, VerifierOnly};
