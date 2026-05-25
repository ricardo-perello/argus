//! Indexed public input wrappers for prepared protocols.

extern crate alloc;

use alloc::vec::Vec;

use super::CommittedIndexBytes;
use crate::Encoding;

/// Tag prefixed to the canonical encoding of an [`IndexedInstance`].
pub(crate) const INDEXED_INSTANCE_TAG: &[u8] = b"argus:indexed-instance:v1";

/// Public input for a prepared preprocessing protocol: the verifier-index commitment
/// paired with the per-claim instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedInstance<I> {
    committed_index: CommittedIndexBytes,
    instance: I,
}

impl<I> IndexedInstance<I> {
    pub fn new(committed_index: CommittedIndexBytes, instance: I) -> Self {
        Self {
            committed_index,
            instance,
        }
    }

    pub fn committed_index(&self) -> &CommittedIndexBytes {
        &self.committed_index
    }

    pub fn inner(&self) -> &I {
        &self.instance
    }

    pub fn into_inner(self) -> I {
        self.instance
    }
}

/// Borrowed counterpart to [`IndexedInstance`] for backends that want to
/// absorb the pair without forcing `Clone` on the instance type.
pub struct IndexedInstanceRef<'a, I> {
    committed_index: &'a CommittedIndexBytes,
    instance: &'a I,
}

impl<'a, I> IndexedInstanceRef<'a, I> {
    pub fn new(committed_index: &'a CommittedIndexBytes, instance: &'a I) -> Self {
        Self {
            committed_index,
            instance,
        }
    }

    pub fn committed_index(&self) -> &CommittedIndexBytes {
        self.committed_index
    }

    pub fn instance(&self) -> &I {
        self.instance
    }
}

fn encode_indexed_instance<I: Encoding<[u8]>>(
    committed_index: &CommittedIndexBytes,
    instance: &I,
) -> Vec<u8> {
    let committed_encoded = committed_index.encode();
    let committed_bytes = committed_encoded.as_ref();
    let instance_encoded = instance.encode();
    let instance_bytes = instance_encoded.as_ref();

    let instance_len =
        u64::try_from(instance_bytes.len()).expect("instance encoding too large for u64 length");

    let mut out = Vec::with_capacity(
        INDEXED_INSTANCE_TAG.len() + committed_bytes.len() + 8 + instance_bytes.len(),
    );
    out.extend_from_slice(INDEXED_INSTANCE_TAG);
    // committed_index is already length-delimited by its own encoding.
    out.extend_from_slice(committed_bytes);
    out.extend_from_slice(&instance_len.to_le_bytes());
    out.extend_from_slice(instance_bytes);
    out
}

impl<I: Encoding<[u8]>> Encoding<[u8]> for IndexedInstance<I> {
    fn encode(&self) -> impl AsRef<[u8]> {
        encode_indexed_instance(&self.committed_index, &self.instance)
    }
}

impl<I: Encoding<[u8]>> Encoding<[u8]> for IndexedInstanceRef<'_, I> {
    fn encode(&self) -> impl AsRef<[u8]> {
        encode_indexed_instance(self.committed_index, self.instance)
    }
}
