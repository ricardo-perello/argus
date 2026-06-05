use ark_crypto_primitives::merkle_tree::{Config, MerkleTree};

// -----------------------------------------------------------------------
// Accumulator types (same shape as the upstream WARP reference).
// -----------------------------------------------------------------------

/// `(roots, alphas, mus, (taus, xs), etas)`.
pub type AccumulatorInstances<F, MT> = (
    Vec<<MT as Config>::InnerDigest>,
    Vec<Vec<F>>,
    Vec<F>,
    (Vec<Vec<F>>, Vec<Vec<F>>),
    Vec<F>,
);

/// `(merkle_trees, codewords, witness_parts)`.
pub type AccumulatorWitnesses<F, MT> = (Vec<MerkleTree<MT>>, Vec<Vec<F>>, Vec<Vec<F>>);
