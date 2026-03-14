use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{Config, IdentityDigestConverter},
    sponge::Absorb,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::RngCore;
use serde::Deserialize;
use serde::Serialize;
use std::{hash::Hash, marker::PhantomData};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MerkleTreeParams<F, LeafH, CompressH, Digest> {
    #[serde(skip)]
    _marker: PhantomData<(F, LeafH, CompressH, Digest)>,
}

impl<F, LeafH, CompressH, Digest> Config for MerkleTreeParams<F, LeafH, CompressH, Digest>
where
    F: CanonicalSerialize + Send,
    LeafH: CRHScheme<Input = [F], Output = Digest>,
    CompressH: TwoToOneCRHScheme<Input = Digest, Output = Digest>,
    Digest: Clone
        + std::fmt::Debug
        + Default
        + CanonicalSerialize
        + CanonicalDeserialize
        + Eq
        + PartialEq
        + Hash
        + Send
        + Absorb,
{
    type Leaf = [F];
    type LeafDigest = Digest;
    type LeafInnerDigestConverter = IdentityDigestConverter<Digest>;
    type InnerDigest = Digest;
    type LeafHash = LeafH;
    type TwoToOneHash = CompressH;
}

pub fn default_config<F, LeafH, CompressH>(
    rng: &mut impl RngCore,
) -> (
    <LeafH as CRHScheme>::Parameters,
    <CompressH as TwoToOneCRHScheme>::Parameters,
)
where
    F: CanonicalSerialize + Send,
    LeafH: CRHScheme<Input = [F]> + Send,
    CompressH: TwoToOneCRHScheme + Send,
{
    (
        LeafH::setup(rng).expect("Failed to setup Leaf hash"),
        CompressH::setup(rng).expect("Failed to setup Compress hash"),
    )
}
