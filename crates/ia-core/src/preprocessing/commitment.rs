//! Verifier-key commitments and the common preprocessed-key capability.

extern crate alloc;

use alloc::vec::Vec;

use crate::Encoding;

/// Owned, length-prefixed bytes that backends absorb to bind the verifier index.
///
/// The wrapper exists so that the transcript input is canonical and does not
/// rely on the raw-byte identity encoding of `Vec<u8>`. [`CommittedIndexBytes`]
/// encodes as `u64_le(length) || bytes`, which is prefix-free.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommittedIndexBytes(Vec<u8>);

impl CommittedIndexBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn empty() -> Self {
        Self(Vec::new())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Encoding<[u8]> for CommittedIndexBytes {
    fn encode(&self) -> impl AsRef<[u8]> {
        let len = u64::try_from(self.0.len()).expect("committed index length exceeds u64");
        let mut out = Vec::with_capacity(8 + self.0.len());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&self.0);
        out
    }
}

/// Public bytes that DSFS (or any other backend) absorbs before the first
/// challenge to bind the preprocessed verifier index.
///
/// Implementors may return the full verifier key bytes, a hash, or a small
/// tuple of root/digest commitments — whatever is appropriate for the soundness
/// argument of the surrounding protocol. The only invariants are that the
/// returned bytes are deterministic and canonical for a given verifier key.
pub trait VerifierKeyCommitment {
    fn committed_index(&self) -> CommittedIndexBytes;
}

impl VerifierKeyCommitment for () {
    fn committed_index(&self) -> CommittedIndexBytes {
        CommittedIndexBytes::empty()
    }
}

/// What the indexer ships to the prover: the author's prover material (`key`)
/// paired with the public verifier-index digest (`committed_index`).
///
/// The digest is computed once, from the verifier key (`vk.committed_index()`),
/// and cached here so the prover — which never holds `vk` — can bind it into the
/// transcript. It is *not* stored on the verifier key, which derives the same
/// digest on demand; there is no duplication and no risk of the two drifting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvingKey<PK> {
    pub key: PK,
    pub committed_index: CommittedIndexBytes,
}

impl<PK> ProvingKey<PK> {
    pub fn new(key: PK, committed_index: CommittedIndexBytes) -> Self {
        Self {
            key,
            committed_index,
        }
    }
}

/// Fixed tag for the canonical pair commitment of two verifier keys.
pub(crate) const VK_PAIR_TAG: &[u8] = b"argus:vk-pair:v1";

impl<V1, V2> VerifierKeyCommitment for (V1, V2)
where
    V1: VerifierKeyCommitment,
    V2: VerifierKeyCommitment,
{
    fn committed_index(&self) -> CommittedIndexBytes {
        let c1 = self.0.committed_index();
        let c1_enc = c1.encode();
        let c1_bytes = c1_enc.as_ref();
        let c2 = self.1.committed_index();
        let c2_enc = c2.encode();
        let c2_bytes = c2_enc.as_ref();

        let c1_len = u64::try_from(c1_bytes.len()).expect("commitment too large for u64 length");
        let c2_len = u64::try_from(c2_bytes.len()).expect("commitment too large for u64 length");

        let mut out =
            Vec::with_capacity(VK_PAIR_TAG.len() + 8 + c1_bytes.len() + 8 + c2_bytes.len());
        out.extend_from_slice(VK_PAIR_TAG);
        out.extend_from_slice(&c1_len.to_le_bytes());
        out.extend_from_slice(c1_bytes);
        out.extend_from_slice(&c2_len.to_le_bytes());
        out.extend_from_slice(c2_bytes);
        CommittedIndexBytes::new(out)
    }
}
