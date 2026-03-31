//! Prover-message deserialization bridging spongefish codecs.

use crate::error::{VerificationError, VerificationResult};

/// Reconstruct a typed value from a byte buffer.
///
/// This is the inverse of [`Encoding`]: given the serialized bytes of a
/// prover message, produce the original value.  Blanket-implemented for
/// every type that has [`spongefish::NargDeserialize`].
pub trait Deserialize: spongefish::NargDeserialize {
    fn deserialize(buf: &mut &[u8]) -> VerificationResult<Self>;
}

impl<T: spongefish::NargDeserialize> Deserialize for T {
    fn deserialize(buf: &mut &[u8]) -> VerificationResult<Self> {
        T::deserialize_from_narg(buf).map_err(|_| VerificationError)
    }
}


// TODO: why is this necessary?