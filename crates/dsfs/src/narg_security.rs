//! NARG security bounds combining IA/IR metadata with sponge parameters.

extern crate alloc;

use ia_core::{ProtocolSecurity, SecurityProfile};

use crate::params::{SpongeParams, STD_SPONGE_PARAMS};

/// Final NARG security profile after applying DSFS to an IA/IR.
#[derive(Debug, Clone)]
pub struct NargSecurity {
    pub ia: SecurityProfile,
    pub sponge: SpongeParams,
}

/// NARG security for a protocol under the standard sponge.
pub fn security<P: ProtocolSecurity>() -> NargSecurity {
    NargSecurity::for_protocol::<P>()
}

/// NARG security for an interactive reduction under the standard sponge.
pub fn reduction_security<P: ProtocolSecurity>() -> NargSecurity {
    NargSecurity::for_protocol::<P>()
}

impl NargSecurity {
    /// Security for a protocol under the standard sponge.
    pub fn for_protocol<P: ProtocolSecurity>() -> Self {
        Self { ia: P::security(), sponge: STD_SPONGE_PARAMS }
    }

    /// Security for a protocol under a custom sponge configuration.
    pub fn for_protocol_with<P: ProtocolSecurity>(sponge: SpongeParams) -> Self {
        Self { ia: P::security(), sponge }
    }

    /// Security for an IA under the standard sponge.
    pub fn for_ia<IA: ProtocolSecurity>() -> Self {
        Self { ia: IA::security(), sponge: STD_SPONGE_PARAMS }
    }

    /// Security for an IR under the standard sponge.
    pub fn for_reduction<IR: ProtocolSecurity>() -> Self {
        Self { ia: IR::security(), sponge: STD_SPONGE_PARAMS }
    }

    /// Security for an IA under a custom sponge configuration.
    pub fn for_ia_with<IA: ProtocolSecurity>(sponge: SpongeParams) -> Self {
        Self { ia: IA::security(), sponge }
    }

    /// Security for an IR under a custom sponge configuration.
    pub fn for_reduction_with<IR: ProtocolSecurity>(sponge: SpongeParams) -> Self {
        Self { ia: IR::security(), sponge }
    }

    /// Theorem 1: `eps_narg(t) <= eps_sr_ip(t) + 25*t^2/|Sigma|^c`.
    pub fn soundness_error(&self, t: u64) -> f64 {
        let t_f = t as f64;
        self.ia.soundness_error.evaluate(t)
            + 25.0 * t_f * t_f / self.sponge_sigma_to(self.sponge.capacity)
    }

    /// Theorem 1: `kappa_narg(t) <= kappa_sr_ip(t) + 25*t^2/|Sigma|^c`.
    pub fn knowledge_soundness_error(&self, t: u64) -> f64 {
        let t_f = t as f64;
        self.ia.knowledge_soundness_error.evaluate(t)
            + 25.0 * t_f * t_f / self.sponge_sigma_to(self.sponge.capacity)
    }

    /// Theorem 2: `z_narg(t) <= z_ip(t) + t/|Sigma|^min(delta,c) + t*sum_i ceil(lV(i)/r)/|Sigma|^(r+c)`.
    pub fn zk_error(&self, t: u64) -> f64 {
        let t_f = t as f64;
        let min_delta_c = self.sponge.delta.min(self.sponge.capacity);
        let challenge_blocks: u64 = self
            .ia
            .verifier_challenge_lengths
            .iter()
            .map(|&l_vi| (l_vi as u64).div_ceil(self.sponge.rate))
            .sum();

        self.ia.hvzk_error.evaluate(t)
            + t_f / self.sponge_sigma_to(min_delta_c)
            + t_f * challenge_blocks as f64
                / self.sponge_sigma_to(self.sponge.rate + self.sponge.capacity)
    }

    pub fn soundness_bits(&self, t: u64) -> f64 {
        -self.soundness_error(t).log2()
    }

    pub fn knowledge_soundness_bits(&self, t: u64) -> f64 {
        -self.knowledge_soundness_error(t).log2()
    }

    pub fn zk_bits(&self, t: u64) -> f64 {
        -self.zk_error(t).log2()
    }

    fn sponge_sigma_to(&self, exponent: u64) -> f64 {
        self.sponge.alphabet_size.powf(exponent as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::NargSecurity;
    use crate::params::SpongeParams;
    use ia_core::{SecurityErrorBound, SecurityProfile};

    #[test]
    fn theorem1_bounds_are_applied() {
        let sec = NargSecurity {
            ia: SecurityProfile {
                soundness_error: SecurityErrorBound::new(|_t| 0.01),
                knowledge_soundness_error: SecurityErrorBound::new(|_t| 0.02),
                hvzk_error: SecurityErrorBound::new(|_t| 0.03),
                num_rounds: 2,
                verifier_challenge_lengths: alloc::vec![5, 7],
            },
            sponge: SpongeParams {
                alphabet_size: 2.0,
                capacity: 4,
                rate: 3,
                delta: 2,
            },
        };

        let t = 2_u64;
        let additive = 25.0 * (t as f64) * (t as f64) / 2_f64.powf(4.0);
        assert!((sec.soundness_error(t) - (0.01 + additive)).abs() < 1e-12);
        assert!((sec.knowledge_soundness_error(t) - (0.02 + additive)).abs() < 1e-12);
    }

    #[test]
    fn theorem1_with_t_dependent_ia_error() {
        fn ia_soundness(t: u64) -> f64 {
            (t as f64) / 1_000_000.0
        }

        let sec = NargSecurity {
            ia: SecurityProfile {
                soundness_error: SecurityErrorBound::new(ia_soundness),
                knowledge_soundness_error: SecurityErrorBound::zero(),
                hvzk_error: SecurityErrorBound::zero(),
                num_rounds: 1,
                verifier_challenge_lengths: alloc::vec![1],
            },
            sponge: SpongeParams {
                alphabet_size: 256.0,
                capacity: 2,
                rate: 2,
                delta: 1,
            },
        };

        let t = 100_u64;
        let expected_ia = 100.0 / 1_000_000.0;
        let expected_sponge = 25.0 * 100.0 * 100.0 / 256.0_f64.powf(2.0);
        assert!((sec.soundness_error(t) - (expected_ia + expected_sponge)).abs() < 1e-12);
    }

    #[test]
    fn theorem2_bound_is_applied() {
        let sec = NargSecurity {
            ia: SecurityProfile {
                soundness_error: SecurityErrorBound::zero(),
                knowledge_soundness_error: SecurityErrorBound::zero(),
                hvzk_error: SecurityErrorBound::new(|_t| 0.125),
                num_rounds: 2,
                verifier_challenge_lengths: alloc::vec![5, 7],
            },
            sponge: SpongeParams {
                alphabet_size: 2.0,
                capacity: 4,
                rate: 3,
                delta: 2,
            },
        };

        let t = 2_u64;
        // ceil(5/3) + ceil(7/3) = 2 + 3 = 5.
        let expected = 0.125 + 2.0 / 2_f64.powf(2.0) + 2.0 * 5.0 / 2_f64.powf(7.0);
        assert!((sec.zk_error(t) - expected).abs() < 1e-12);
    }

    #[test]
    fn security_error_bound_composes_additively() {
        let a = SecurityErrorBound::new(|t| t as f64);
        let b = SecurityErrorBound::new(|t| 2.0 * t as f64);
        let c = a.compose(&b);
        assert!((c.evaluate(10) - 30.0).abs() < 1e-12);
    }
}
