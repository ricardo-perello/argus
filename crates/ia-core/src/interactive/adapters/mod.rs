//! Interactive adapters between plain and preprocessing protocol surfaces.

mod plain_to_preprocessing;

pub use plain_to_preprocessing::{
    TrivialIndexedArgumentProver, TrivialIndexedArgumentVerifier, TrivialIndexedReductionProver,
    TrivialIndexedReductionVerifier, TrivialIndexer,
};
