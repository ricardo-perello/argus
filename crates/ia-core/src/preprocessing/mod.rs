//! Preprocessing commitments and indexed public-input wrappers.

mod commitment;
mod instance;

#[cfg(test)]
pub(crate) use commitment::VK_PAIR_TAG;
pub use commitment::{CommittedIndexBytes, ProvingKey, VerifierKeyCommitment};
#[cfg(test)]
pub(crate) use instance::INDEXED_INSTANCE_TAG;
pub use instance::{IndexedInstance, IndexedInstanceRef};
