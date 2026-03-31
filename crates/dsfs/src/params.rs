//! Sponge shape and DSFS security-parameter bookkeeping for duplex sponges.

use spongefish::{DuplexSponge, Permutation};

/// Sponge parameters needed to evaluate DSFS security bounds.
#[derive(Debug, Clone, Copy)]
pub struct SpongeParams {
    /// Alphabet size `|Sigma|`.
    pub alphabet_size: f64,
    /// Sponge capacity `c`.
    pub capacity: u64,
    /// Sponge rate `r`.
    pub rate: u64,
    /// Codec/domain parameter `delta`.
    pub delta: u64,
}

/// Parameters for the standard sponge used by this crate (`Keccak-f[1600]`, rate 136).
///
/// Matches [`DuplexSpongeParamsExt::sponge_params`] on a default [`Keccak`] duplex sponge.
pub const STD_SPONGE_PARAMS: SpongeParams = SpongeParams {
    alphabet_size: 256.0,
    capacity: 64,
    rate: 136,
    delta: 1,
};

pub type Keccak = spongefish::instantiations::Keccak;

/// Spongefish’s default FS transcript hash: SHAKE128 in XOF duplex mode (`std_prover` / `std_verifier`).
///
/// Use with [`crate::compile::prove_with_sponge`] when you need byte-compatibility with
/// spongefish / σ-proofs `Nizk` transcript defaults.
pub type StdHash = spongefish::StdHash;

/// 32-byte sponge tag appended to the 32-byte IA protocol id to form the full
/// 64-byte DSFS domain separator: `[ia_id: 32 || sponge_tag: 32]`.
///
/// Mirrors sigma-proofs’ convention of embedding the hash-function name in the
/// ASCII ciphersuite label, but keeps it separate from the IA identity so the
/// same IA can be compiled with different sponges without changing its `protocol_id`.
pub trait SpongeTag: super::compile::ByteDuplexSponge {
    const TAG: [u8; 32];
}

const fn pad_tag(label: &[u8]) -> [u8; 32] {
    let mut tag = [0u8; 32];
    let mut i = 0;
    while i < label.len() && i < 32 {
        tag[i] = label[i];
        i += 1;
    }
    tag
}

impl SpongeTag for Keccak {
    const TAG: [u8; 32] = pad_tag(b"keccak");
}

impl SpongeTag for StdHash {
    const TAG: [u8; 32] = pad_tag(b"shake128");
}

/// Bookkeeping parameters for DSFS bounds when the transcript uses [`StdHash`] (SHAKE128 XOF).
///
/// The XOF duplex in spongefish does not expose a fixed classical sponge width; this uses the
/// rate from σ-proofs’ session-id helper (`RATE = 168`, SHAKE padding block) and treats capacity
/// as **32 bytes (256 bits)** for conservative bound evaluation. Prefer [`STD_SPONGE_PARAMS`] for
/// the default Keccak-`p[1600]` construction used in Argus.
pub const STD_HASH_SPONGE_PARAMS: SpongeParams = SpongeParams {
    alphabet_size: 256.0,
    capacity: 32,
    rate: 168,
    delta: 1,
};

/// Extension trait: derive [`SpongeParams`] for DSFS security bounds from a duplex sponge’s
/// width and rate (`capacity = width - rate`, byte alphabet, `delta = 1`).
pub trait DuplexSpongeParamsExt {
    fn sponge_params(&self) -> SpongeParams;
}

impl<P, const WIDTH: usize, const RATE: usize> DuplexSpongeParamsExt
    for DuplexSponge<P, WIDTH, RATE>
where
    P: Permutation<WIDTH>,
{
    fn sponge_params(&self) -> SpongeParams {
        SpongeParams {
            alphabet_size: 256.0,
            capacity: (WIDTH - RATE) as u64,
            rate: RATE as u64,
            delta: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DuplexSpongeParamsExt, Keccak, STD_HASH_SPONGE_PARAMS, STD_SPONGE_PARAMS};

    #[test]
    fn std_sponge_params_matches_keccak_duplex_ext() {
        let from_ext = Keccak::default().sponge_params();
        assert_eq!(from_ext.capacity, STD_SPONGE_PARAMS.capacity);
        assert_eq!(from_ext.rate, STD_SPONGE_PARAMS.rate);
        assert_eq!(from_ext.delta, STD_SPONGE_PARAMS.delta);
        assert!((from_ext.alphabet_size - STD_SPONGE_PARAMS.alphabet_size).abs() < 1e-12);
    }

    #[test]
    fn std_hash_sponge_params_is_documented_constant() {
        assert_eq!(STD_HASH_SPONGE_PARAMS.alphabet_size, 256.0);
        assert_eq!(STD_HASH_SPONGE_PARAMS.capacity, 32);
        assert_eq!(STD_HASH_SPONGE_PARAMS.rate, 168);
        assert_eq!(STD_HASH_SPONGE_PARAMS.delta, 1);
    }
}
