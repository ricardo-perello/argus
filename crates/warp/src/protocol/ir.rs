use std::marker::PhantomData;

use ark_codes::traits::LinearCode;
use ark_crypto_primitives::merkle_tree::{Config, MerkleTree};
use ark_ff::{Field, PrimeField};
use ark_poly::{DenseMultilinearExtension, Polynomial};
use ark_std::log2;

use ia_core::{
    CodeSecurityParams, InteractiveArgument, InteractiveReduction, ProtocolSecurity, ProverChannel,
    ReducedArgument, SecurityErrorBound, SecurityProfile, VerificationResult, VerifierChannel,
};

use crate::rs_params::ReedSolomonParams;

use crate::protocol::warp::{DeciderInstance, DeciderWitness, WARPInstance, WARPWitness};
use crate::relations::r1cs::R1CSConstraints;
use crate::relations::BundledPESAT;
use crate::utils::poly::{eq_poly, Hypercube};

// -----------------------------------------------------------------------
// WARPReduction: the full IOR as a single InteractiveReduction
// -----------------------------------------------------------------------

pub struct WARPReduction<F, P, C, MT> {
    /// Number of twin-sumcheck folding rounds (= log2 of total instance count l).
    pub log_l: usize,
    /// Number of batching-sumcheck rounds (= log2 of codeword length n).
    pub log_n: usize,
    /// log2 of the number of R1CS constraints M. Used to compute the polynomial
    /// degree for the twin sumcheck per-round RBR error bound.
    pub log_m: usize,
    /// Reed-Solomon code security parameters (n, k, |F|-bits).
    /// Used by `ProtocolSecurity::security()` to compute the full paper bounds.
    pub code_params: ReedSolomonParams,
    /// Number of OOD samples s (from `WARPConfig.s`).
    pub ood_samples: usize,
    /// Number of shift queries t (from `WARPConfig.t`).
    pub shift_queries: usize,
    _phantom: PhantomData<(F, P, C, MT)>,
}

impl<F, P, C, MT> WARPReduction<F, P, C, MT> {
    pub fn new(
        log_l: usize,
        log_n: usize,
        log_m: usize,
        code_params: ReedSolomonParams,
        ood_samples: usize,
        shift_queries: usize,
    ) -> Self {
        Self {
            log_l,
            log_n,
            log_m,
            code_params,
            ood_samples,
            shift_queries,
            _phantom: PhantomData,
        }
    }
}

impl<F, P, C, MT> InteractiveReduction for WARPReduction<F, P, C, MT>
where
    F: Field
        + PrimeField
        + Send
        + Sync
        + spongefish::Encoding
        + spongefish::Decoding
        + ia_core::Deserialize,
    P: Clone + BundledPESAT<F, Constraints = R1CSConstraints<F>, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone,
    MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
{
    type SourceInstance = WARPInstance<F, P, C, MT>;
    type SourceWitness = WARPWitness<F, MT>;
    type TargetInstance = DeciderInstance<F, P, C, MT>;
    type TargetWitness = DeciderWitness<F, MT>;

    fn protocol_id(&self) -> impl AsRef<[u8]> {
        ia_core::pad_protocol_id(b"argus::warp::reduction")
    }

    fn prove<Ch: ProverChannel>(
        &self,
        ch: &mut Ch,
        instance: &WARPInstance<F, P, C, MT>,
        witness: &WARPWitness<F, MT>,
    ) -> (DeciderInstance<F, P, C, MT>, DeciderWitness<F, MT>) {
        let warp = &instance.warp;
        let pk = &instance.pk;

        let (acc_instance, acc_witness, _proof_data) = warp
            .prove_with_channel(
                ch,
                pk,
                &instance.instances,
                &witness.witnesses,
                &instance.acc_instances,
                &witness.acc_witnesses,
            )
            .expect("honest prover must not fail");

        let target_instance = DeciderInstance {
            warp: instance.warp.clone(),
            acc_instance,
        };
        (target_instance, acc_witness)
    }

    fn verify<Ch: VerifierChannel>(
        &self,
        ch: &mut Ch,
        instance: &WARPInstance<F, P, C, MT>,
    ) -> VerificationResult<DeciderInstance<F, P, C, MT>> {
        let warp = &instance.warp;
        let vk = (instance.pk.1, instance.pk.2, instance.pk.3);

        let result = warp
            .verify_reduction_transcript(ch, vk)
            .map_err(|_| ia_core::VerificationError)?;
        let acc_instance = result.target;

        Ok(DeciderInstance {
            warp: instance.warp.clone(),
            acc_instance,
        })
    }
}

impl<F, P, C, MT> ProtocolSecurity for WARPReduction<F, P, C, MT>
where
    F: PrimeField,
    P: BundledPESAT<F>,
    C: LinearCode<F> + Clone,
    MT: Config,
{
    fn security(&self) -> SecurityProfile {
        // Security bounds follow eprint 2025/753.
        //
        // Twin sumcheck (log_l rounds, §6.1–6.2):
        //   degree   = 1 + max(log_n + 1, log_m + 2)  [warp.rs:293 + eprint §6.1, d=2]
        //   per-round RBR error at round j (0-indexed):
        //     Schwartz–Zippel:   deg / |F|
        //     errPG contribution: (ℓ / 2^j) · err_PG(C, 2, δ)  [§6.2]
        //
        // Batching sumcheck (log_n rounds, §8):
        //   degree 2 (sends sum_00, sum_11, sum_0110)
        //   per-round RBR error: 2 / |F|
        //
        // Commitment / OOD / PESAT terms (non-SR, one-time costs, §5.2 + §7):
        //   |Λ(C,δ)|² · log_n / |F|  +  (1 − δ)^shift_queries  +  |Λ| · log_M / |F|
        //   These don't participate in the SR adversary budget — they are absorbed
        //   in the commitment phase and do not correspond to interactive rounds.
        //   Placed in plain_soundness_error pending Q2 confirmation with Chiesa.
        //
        // WARP is public-coin with no ZK, so hvzk_error = 0.

        let field_bits = F::MODULUS_BIT_SIZE as i32;
        let field_inv = 2_f64.powi(-field_bits);

        // Code-specific parameters.
        let delta = self.code_params.distance();
        let list_size = self.code_params.list_size_bound();
        // err_PG for degree 2 (quadratic R1CS, eprint §6.2).
        let err_pg = self.code_params.proximity_generator_error(2);
        let ell = (1usize << self.log_l) as f64;

        // Twin sumcheck degree = 1 + max(log_n + 1, log_m + 2).
        let twin_deg = 1 + (self.log_n + 1).max(self.log_m + 2);

        // Twin sumcheck RBR bounds: round j (0-indexed) adds Schwartz–Zippel + errPG.
        let twin_rbr: Vec<SecurityErrorBound> = (0..self.log_l)
            .map(|j| {
                let sz = (twin_deg as f64) * field_inv;
                let pg = (ell / (1u64 << j) as f64) * err_pg;
                SecurityErrorBound::new(move |_t| sz + pg)
            })
            .collect();

        // Batching sumcheck RBR bounds: degree 2 per round.
        let batch_rbr: Vec<SecurityErrorBound> = (0..self.log_n)
            .map(|_| SecurityErrorBound::new(move |_t| 2.0 * field_inv))
            .collect();

        let mut rbr = twin_rbr;
        rbr.extend(batch_rbr);

        // One-time (non-SR) commitment-phase terms.
        // OOD + shift-sampling (§7): |Λ|² · log_n / |F| + (1 − δ)^shift_queries
        let log_n_f = self.log_n as f64;
        let ood_term = list_size * list_size * log_n_f * field_inv;
        let shift_term = (1.0 - delta).powi(self.shift_queries as i32);
        // PESAT → code reduction (§5.2): |Λ| · log_M / |F|
        let log_m_f = self.log_m as f64;
        let pesat_term = list_size * log_m_f * field_inv;

        let plain_error = SecurityErrorBound::new(move |_t| ood_term + shift_term + pesat_term);

        SecurityProfile {
            plain_soundness_error: plain_error,
            rbr_soundness_errors: rbr.clone(),
            rbr_knowledge_soundness_errors: rbr,
            hvzk_error: SecurityErrorBound::zero(),
            // Each round squeezes one field element as a challenge.
            verifier_challenge_lengths: vec![1; self.log_l + self.log_n],
        }
    }
}

// -----------------------------------------------------------------------
// WARPDeciderIA: the decider as an InteractiveArgument
// -----------------------------------------------------------------------

pub struct WARPDeciderIA<F, P, C, MT>(pub PhantomData<(F, P, C, MT)>);

impl<F, P, C, MT> Default for WARPDeciderIA<F, P, C, MT> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<F, P, C, MT> InteractiveArgument for WARPDeciderIA<F, P, C, MT>
where
    F: Field
        + PrimeField
        + Send
        + Sync
        + spongefish::Encoding
        + spongefish::Decoding
        + ia_core::Deserialize,
    P: Clone + BundledPESAT<F, Constraints = R1CSConstraints<F>, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone,
    MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
{
    type Instance = DeciderInstance<F, P, C, MT>;
    type Witness = DeciderWitness<F, MT>;

    fn protocol_id(&self) -> impl AsRef<[u8]> {
        ia_core::pad_protocol_id(b"argus::warp::decider")
    }

    fn prove<Ch: ProverChannel>(
        &self,
        ch: &mut Ch,
        _instance: &DeciderInstance<F, P, C, MT>,
        witness: &DeciderWitness<F, MT>,
    ) {
        let (_trees, codewords, w_parts) = witness;
        for val in &codewords[0] {
            ch.send_prover_message(val);
        }
        for val in &w_parts[0] {
            ch.send_prover_message(val);
        }
    }

    fn verify<Ch: VerifierChannel>(
        &self,
        ch: &mut Ch,
        instance: &DeciderInstance<F, P, C, MT>,
    ) -> VerificationResult<()> {
        let warp = &instance.warp;
        let (rt, alpha, mu, beta, eta) = &instance.acc_instance;
        let n = warp.code.code_len();
        let log_n = log2(n) as usize;

        let mut f = vec![F::default(); n];
        for val in f.iter_mut() {
            *val = ch.read_prover_message()?;
        }

        let k = warp.config.p_conf.2;
        let mut w = vec![F::default(); k];
        for val in w.iter_mut() {
            *val = ch.read_prover_message()?;
        }

        let computed_mt = MerkleTree::<MT>::new(
            &warp.mt_leaf_hash_params,
            &warp.mt_two_to_one_hash_params,
            f.chunks(1).collect::<Vec<_>>(),
        )
        .map_err(|_| ia_core::VerificationError)?;
        if rt[0] != computed_mt.root() {
            return Err(ia_core::VerificationError);
        }

        let f_hat = DenseMultilinearExtension::from_evaluations_slice(log_n, &f);
        if f_hat.evaluate(&alpha[0]) != mu[0] {
            return Err(ia_core::VerificationError);
        }

        let tau_val = &beta.0[0];
        let tau_zero_evader: Vec<F> = Hypercube::new(tau_val.len())
            .map(|index| eq_poly(tau_val, index))
            .collect();

        let mut z = beta.1[0].clone();
        z.extend(w.clone());
        let computed_eta = warp
            .p
            .evaluate_bundled(&tau_zero_evader, &z)
            .map_err(|_| ia_core::VerificationError)?;
        if computed_eta != eta[0] {
            return Err(ia_core::VerificationError);
        }

        let computed_f = warp.code.encode(&w);
        if f != computed_f {
            return Err(ia_core::VerificationError);
        }

        Ok(())
    }
}

impl<F, P, C, MT> ProtocolSecurity for WARPDeciderIA<F, P, C, MT>
where
    F: Field,
    P: BundledPESAT<F>,
    C: LinearCode<F> + Clone,
    MT: Config,
{
    fn security(&self) -> SecurityProfile {
        // The decider is a deterministic local check (no challenges, no rounds).
        SecurityProfile {
            plain_soundness_error: SecurityErrorBound::zero(),
            rbr_soundness_errors: Vec::new(),
            rbr_knowledge_soundness_errors: Vec::new(),
            hvzk_error: SecurityErrorBound::zero(),
            verifier_challenge_lengths: Vec::new(),
        }
    }
}

// -----------------------------------------------------------------------
// FullWARP = ReducedArgument<WARPReduction, WARPDeciderIA>  (IR . IA -> IA)
// -----------------------------------------------------------------------

pub type FullWARP<F, P, C, MT> =
    ReducedArgument<WARPReduction<F, P, C, MT>, WARPDeciderIA<F, P, C, MT>>;
