use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::Config,
};
use ark_ff::Field;
use ark_serialize::CanonicalSerialize;

pub mod batching_sumcheck;
pub(crate) mod commitment;
pub mod ir;
pub mod twin_sumcheck;
pub mod warp;

/// Bundles the Merkle-tree configuration bounds WARP needs — leaf type `[F]`,
/// 32-byte digests, and serializable hash parameters — so protocol signatures
/// stop repeating the same four-line `where` clause.
///
/// All bounds are supertrait / associated-type bounds (no `where` clause), so
/// they elaborate as *implied* bounds at every `MT: WarpMerkle<F>` use site. The
/// blanket impl below makes any `Config` meeting them a `WarpMerkle`
/// automatically — callers never implement it by hand.
pub trait WarpMerkle<F: Field>:
    Config<
    Leaf = [F],
    InnerDigest: AsRef<[u8]> + From<[u8; 32]>,
    LeafHash: CRHScheme<Parameters: CanonicalSerialize>,
    TwoToOneHash: TwoToOneCRHScheme<Parameters: CanonicalSerialize>,
>
{
}

impl<F, MT> WarpMerkle<F> for MT
where
    F: Field,
    MT: Config<
        Leaf = [F],
        InnerDigest: AsRef<[u8]> + From<[u8; 32]>,
        LeafHash: CRHScheme<Parameters: CanonicalSerialize>,
        TwoToOneHash: TwoToOneCRHScheme<Parameters: CanonicalSerialize>,
    >,
{
}
