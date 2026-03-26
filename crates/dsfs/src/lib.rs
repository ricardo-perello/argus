//! DSFS compiler: Duplex-Sponge Fiat-Shamir transformation (Construction 4.3, Chiesa-Orru 2025).
//!
//! Wraps spongefish's `ProverState` and `VerifierState` behind ia-core's
//! abstract channel traits. This is the **only** layer that touches the sponge.
//!
//! Supports both interactive arguments (`prove`/`verify`) and interactive
//! oracle reductions (`prove_reduction`/`verify_reduction`).
#![no_std]
extern crate alloc;

use alloc::vec::Vec;

use rand_core::RngCore;
use ia_core::{
    Deserialize, InteractiveArgument, InteractiveReduction, Prove, ProverChannel, ReduceProve,
    ReduceVerify, SecurityProfile, VerifierChannel, Verify,
};
use spongefish::{
    Decoding, DomainSeparator, Encoding, Permutation, ProverState, VerifierState,
};

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
pub const STD_SPONGE_PARAMS: SpongeParams = SpongeParams {
    alphabet_size: 256.0,
    capacity: 64,
    rate: 136,
    delta: 1,
};

pub type Keccak = spongefish::instantiations::Keccak;

pub fn sponge_params_from_duplex_sponge<
    P: Permutation<WIDTH>,
    const WIDTH: usize,
    const RATE: usize,
>() -> SpongeParams {
    let _ = core::marker::PhantomData::<P>;
    SpongeParams {
        alphabet_size: 256.0,
        capacity: (WIDTH - RATE) as u64,
        rate: RATE as u64,
        delta: 1,
    }
}


/// Final NARG security profile after applying DSFS to an IA/IR.
#[derive(Debug, Clone)]
pub struct NargSecurity {
    pub ia: SecurityProfile,
    pub sponge: SpongeParams,
}

/// NARG security for an `InteractiveArgument` under the standard sponge.
pub fn security<IA: InteractiveArgument>() -> NargSecurity {
    NargSecurity::for_ia::<IA>()
}

/// NARG security for an `InteractiveReduction` under the standard sponge.
pub fn reduction_security<IR: InteractiveReduction>() -> NargSecurity {
    NargSecurity::for_reduction::<IR>()
}

impl NargSecurity {
    /// Security for an IA under the standard sponge.
    pub fn for_ia<IA: InteractiveArgument>() -> Self {
        Self { ia: IA::security(), sponge: STD_SPONGE_PARAMS }
    }

    /// Security for an IR under the standard sponge.
    pub fn for_reduction<IR: InteractiveReduction>() -> Self {
        Self { ia: IR::security(), sponge: STD_SPONGE_PARAMS }
    }

    /// Security for an IA under a custom sponge configuration.
    pub fn for_ia_with<IA: InteractiveArgument>(sponge: SpongeParams) -> Self {
        Self { ia: IA::security(), sponge }
    }

    /// Security for an IR under a custom sponge configuration.
    pub fn for_reduction_with<IR: InteractiveReduction>(sponge: SpongeParams) -> Self {
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

// ---------------------------------------------------------------------------
// Sponge-backed channel: prover side
// ---------------------------------------------------------------------------

/// Wraps `spongefish::ProverState` as an ia-core `ProverChannel`.
pub struct SpongeProver {
    state: ProverState<Keccak>,
}

impl SpongeProver {
    pub fn new(state: ProverState<Keccak>) -> Self {
        Self { state }
    }

    pub fn narg_string(&self) -> &[u8] {
        self.state.narg_string()
    }
}

impl ProverChannel for SpongeProver {
    fn send_prover_message<PM: Encoding>(&mut self, msg: &PM) {
        self.state.prover_message(msg);
    }

    fn read_verifier_message<VM: Decoding>(&mut self) -> VM {
        self.state.verifier_message()
    }
}

// ---------------------------------------------------------------------------
// Sponge-backed channel: verifier side
// ---------------------------------------------------------------------------

/// Wraps `spongefish::VerifierState` as an ia-core `VerifierChannel`.
pub struct SpongeVerifier<'a> {
    state: VerifierState<'a, Keccak>,
}

impl<'a> SpongeVerifier<'a> {
    pub fn new(state: VerifierState<'a, Keccak>) -> Self {
        Self { state }
    }
}

impl VerifierChannel for SpongeVerifier<'_> {
    fn read_prover_message<PM: Encoding + Deserialize>(
        &mut self,
    ) -> ia_core::VerificationResult<PM> {
        self.state
            .prover_message()
            .map_err(|_| ia_core::VerificationError)
    }

    fn send_verifier_message<VM: Decoding>(&mut self) -> VM {
        self.state.verifier_message()
    }
}

// ---------------------------------------------------------------------------
// DSFS compiler functions
// ---------------------------------------------------------------------------

/// Non-interactive prover with explicit salt length.
pub fn prove_with_salt<IA, const SALT_LEN: usize>(
    session: [u8; 64],
    instance: &IA::Instance,
    witness: &IA::Witness,
) -> Vec<u8>
where
    IA: Prove<SpongeProver>,
    IA::Instance: Encoding,
{
    let domsep = DomainSeparator::new(IA::protocol_id())
        .session(session)
        .instance(instance);

    let mut spongefish_prover_ch = SpongeProver::new(domsep.to_prover(Keccak::default()));
    let mut salt = [0u8; SALT_LEN];
    spongefish_prover_ch.state.rng().fill_bytes(&mut salt);
    spongefish_prover_ch.state.prover_message(&salt);
    IA::prove(&mut spongefish_prover_ch, instance, witness);
    spongefish_prover_ch.narg_string().to_vec()
}

/// Non-interactive prover with default `SALT_LEN = 0`.
pub fn prove<IA>(
    session: [u8; 64],
    instance: &IA::Instance,
    witness: &IA::Witness,
) -> Vec<u8>
where
    IA: Prove<SpongeProver>,
    IA::Instance: Encoding,
{
    prove_with_salt::<IA, 0>(session, instance, witness)
}

/// Non-interactive verifier with explicit salt length.
pub fn verify_with_salt<'a, IA, const SALT_LEN: usize>(
    session: [u8; 64],
    instance: &IA::Instance,
    proof: &'a [u8],
) -> ia_core::VerificationResult<()>
where
    IA: Verify<SpongeVerifier<'a>>,
    IA::Instance: Encoding,
{
    let domsep = DomainSeparator::new(IA::protocol_id())
        .session(session)
        .instance(instance);

    let mut spongefish_verifier_ch =
        SpongeVerifier::new(domsep.to_verifier(Keccak::default(), proof));
    let _salt: [u8; SALT_LEN] = spongefish_verifier_ch
        .state
        .prover_message()
        .map_err(|_| ia_core::VerificationError)?;
    IA::verify(&mut spongefish_verifier_ch, instance)?;
    spongefish_verifier_ch
        .state
        .check_eof()
        .map_err(|_| ia_core::VerificationError)
}

/// Non-interactive verifier with default `SALT_LEN = 0`.
pub fn verify<'a, IA>(
    session: [u8; 64],
    instance: &IA::Instance,
    proof: &'a [u8],
) -> ia_core::VerificationResult<()>
where
    IA: Verify<SpongeVerifier<'a>>,
    IA::Instance: Encoding,
{
    verify_with_salt::<IA, 0>(session, instance, proof)
}

// ---------------------------------------------------------------------------
// DSFS compiler functions for interactive reductions
// ---------------------------------------------------------------------------

/// Non-interactive prover for an IOR with explicit salt length.
pub fn prove_reduction_with_salt<IR, const SALT_LEN: usize>(
    session: [u8; 64],
    instance: &IR::SourceInstance,
    witness: &IR::SourceWitness,
) -> Vec<u8>
where
    IR: ReduceProve<SpongeProver>,
    IR::SourceInstance: Encoding,
{
    let domsep = DomainSeparator::new(IR::protocol_id())
        .session(session)
        .instance(instance);

    let mut spongefish_prover_ch = SpongeProver::new(domsep.to_prover(Keccak::default()));
    let mut salt = [0u8; SALT_LEN];
    spongefish_prover_ch.state.rng().fill_bytes(&mut salt);
    spongefish_prover_ch.state.prover_message(&salt);
    let (_target_instance, _target_witness) = IR::prove(&mut spongefish_prover_ch, instance, witness);
    spongefish_prover_ch.narg_string().to_vec()
}

/// Non-interactive prover for an IOR with default `SALT_LEN = 0`.
pub fn prove_reduction<IR>(
    session: [u8; 64],
    instance: &IR::SourceInstance,
    witness: &IR::SourceWitness,
) -> Vec<u8>
where
    IR: ReduceProve<SpongeProver>,
    IR::SourceInstance: Encoding,
{
    prove_reduction_with_salt::<IR, 0>(session, instance, witness)
}

/// Non-interactive verifier for an IOR with explicit salt length.
pub fn verify_reduction_with_salt<'a, IR, const SALT_LEN: usize>(
    session: [u8; 64],
    instance: &IR::SourceInstance,
    proof: &'a [u8],
) -> ia_core::VerificationResult<IR::TargetInstance>
where
    IR: ReduceVerify<SpongeVerifier<'a>>,
    IR::SourceInstance: Encoding,
{
    let domsep = DomainSeparator::new(IR::protocol_id())
        .session(session)
        .instance(instance);

    let mut spongefish_verifier_ch =
        SpongeVerifier::new(domsep.to_verifier(Keccak::default(), proof));
    let _salt: [u8; SALT_LEN] = spongefish_verifier_ch
        .state
        .prover_message()
        .map_err(|_| ia_core::VerificationError)?;
    let target = IR::verify(&mut spongefish_verifier_ch, instance)?;
    spongefish_verifier_ch
        .state
        .check_eof()
        .map_err(|_| ia_core::VerificationError)?;
    Ok(target)
}

/// Non-interactive verifier for an IOR with default `SALT_LEN = 0`.
pub fn verify_reduction<'a, IR>(
    session: [u8; 64],
    instance: &IR::SourceInstance,
    proof: &'a [u8],
) -> ia_core::VerificationResult<IR::TargetInstance>
where
    IR: ReduceVerify<SpongeVerifier<'a>>,
    IR::SourceInstance: Encoding,
{
    verify_reduction_with_salt::<IR, 0>(session, instance, proof)
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use super::{NargSecurity, SpongeParams};
    use ia_core::{SecurityErrorBound, SecurityProfile};

    #[test]
    fn theorem1_bounds_are_applied() {
        let sec = NargSecurity {
            ia: SecurityProfile {
                soundness_error: SecurityErrorBound::new(|_t| 0.01),
                knowledge_soundness_error: SecurityErrorBound::new(|_t| 0.02),
                hvzk_error: SecurityErrorBound::new(|_t| 0.03),
                num_rounds: 2,
                verifier_challenge_lengths: vec![5, 7],
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
                verifier_challenge_lengths: vec![1],
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
                verifier_challenge_lengths: vec![5, 7],
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
