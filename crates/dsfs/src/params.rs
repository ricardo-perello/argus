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

/// Extension trait: derive [`SpongeParams`] for DSFS security bounds from a duplex sponge’s
/// width and rate (`capacity = width - rate`, byte alphabet, `delta = 1`).
pub trait DuplexSpongeParamsExt {
    fn sponge_params(&self) -> SpongeParams;
}

impl<P, const WIDTH: usize, const RATE: usize> DuplexSpongeParamsExt for DuplexSponge<P, WIDTH, RATE>
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
    use super::{DuplexSpongeParamsExt, Keccak, STD_SPONGE_PARAMS};

    #[test]
    fn std_sponge_params_matches_keccak_duplex_ext() {
        let from_ext = Keccak::default().sponge_params();
        assert_eq!(from_ext.capacity, STD_SPONGE_PARAMS.capacity);
        assert_eq!(from_ext.rate, STD_SPONGE_PARAMS.rate);
        assert_eq!(from_ext.delta, STD_SPONGE_PARAMS.delta);
        assert!((from_ext.alphabet_size - STD_SPONGE_PARAMS.alphabet_size).abs() < 1e-12);
    }
}
