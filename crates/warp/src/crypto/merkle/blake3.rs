//! Blake3 Merkle tree wiring for WARP.
//!
//! ark-crypto-primitives 0.6 replaced the old `Blake3` / `Blake3F` /
//! `GenericDigest<N>` types with `Blake3CRH<F>`, `Blake3TwoToOneCRH`, and
//! `ByteDigest<N>`. This module re-exposes them through WARP's
//! [`MerkleTreeParams`] alias so downstream tests can keep referencing
//! `Blake3MerkleTreeParams<F>` unchanged.

use super::parameters::MerkleTreeParams;
use ark_crypto_primitives::crh::{
    blake3::{Blake3CRH, Blake3TwoToOneCRH},
    ByteDigest,
};

pub type Blake3MerkleTreeParams<F> =
    MerkleTreeParams<F, Blake3CRH<F>, Blake3TwoToOneCRH, ByteDigest<32>>;
