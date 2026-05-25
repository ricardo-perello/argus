//! Byte-oriented proof artifact for non-interactive arguments.

extern crate alloc;

use alloc::vec::Vec;

use crate::{Encoding, NargDeserialize, VerificationError, VerificationResult};

/// Opaque byte artifact produced by a non-interactive argument compiler.
///
/// `NargProof` deliberately carries no transcript semantics: sponge choice,
/// salt policy, domain separation, and proof layout are owned by the compiler
/// that produced the bytes.
///
/// The top-level proof artifact is raw bytes: [`NargProof::as_bytes`] and
/// [`NargProof::into_bytes`] expose exactly the byte string emitted by the
/// compiler. When a proof itself is sent as a channel message, its
/// [`Encoding`] implementation is length-delimited as
/// `u64_le(length) || proof_bytes`. This keeps "proof as an artifact" separate
/// from "proof as a typed prover message", where variable-length data must be
/// self-delimiting.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NargProof(Vec<u8>);

impl NargProof {
    /// Wrap raw proof bytes produced by a non-interactive compiler.
    ///
    /// The bytes are not interpreted or normalized.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Consume the proof and return the raw proof bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Borrow the raw proof bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Return the raw proof length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Return whether the raw proof byte string is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[u8]> for NargProof {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Encoding<[u8]> for NargProof {
    fn encode(&self) -> impl AsRef<[u8]> {
        let len = u64::try_from(self.0.len()).expect("NARG proof length exceeds u64");
        let mut out = Vec::with_capacity(8 + self.0.len());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&self.0);
        out
    }
}

impl NargDeserialize for NargProof {
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        let mut rest = *buf;
        let len_bytes: [u8; 8] = NargDeserialize::deserialize_from_narg(&mut rest)?;
        let len = u64::from_le_bytes(len_bytes);
        let len = usize::try_from(len).map_err(|_| VerificationError)?;
        if rest.len() < len {
            return Err(VerificationError);
        }
        let (proof, tail) = rest.split_at(len);
        *buf = tail;
        Ok(Self(proof.to_vec()))
    }
}
