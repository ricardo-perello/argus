//! Codec bindings for common algebraic libraries.

// arkworks-rs
#[cfg(feature = "ark-ec")]
pub mod ark_ec_impl;
#[cfg(feature = "ark-ff")]
pub mod ark_ff_impl;

// zkcrypto
#[cfg(feature = "bls12_381")]
pub mod bls12_381_impl;
#[cfg(feature = "curve25519-dalek")]
pub mod curve25519_dalek_impl;
#[cfg(feature = "p256")]
pub mod p256_impl;
#[cfg(feature = "k256")]
pub mod secp256k1_impl;

// Buffer of 512 bytes, useful for decoding 256-bit scalars.
#[allow(dead_code)]
#[repr(C)]
pub struct Array64(pub(super) [u8; 64]);

impl Default for Array64 {
    fn default() -> Self {
        Self([0u8; 64])
    }
}

impl AsMut<[u8]> for Array64 {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}
