use std::marker::PhantomData;

use ark_codes::traits::LinearCode;
use ark_crypto_primitives::merkle_tree::{Config, MerkleTree};
use ark_ff::{Field, PrimeField};
use ark_poly::{DenseMultilinearExtension, Polynomial};
use ark_std::log2;

use ia_core::{
    ArgumentCore, CommittedIndexBytes, PreprocessingArgumentSecurity, PreprocessingCore,
    PreprocessingInteractiveArgument, PreprocessingInteractiveReduction,
    PreprocessingReductionSecurity, ProtocolCore, ProverChannel, ReducedArgument, ReductionCore,
    SecurityErrorBound, SecurityProfile, VerificationResult, VerifierChannel,
    VerifierKeyCommitment,
};

use crate::protocol::warp::{
    DeciderInstance, DeciderWitness, WARPIndex, WARPInstance, WARPProverKey, WARPVerifierKey,
    WARPWitness,
};
use crate::relations::r1cs::R1CSConstraints;
use crate::relations::BundledPESAT;
use crate::utils::poly::{eq_poly, Hypercube};

// -----------------------------------------------------------------------
// VerifierKeyCommitment
// -----------------------------------------------------------------------

/// Tag prefixed to the canonical bytes returned by
/// [`WARPVerifierKey::committed_index`]. Distinct from any other Argus tag
/// so the prepared DSFS transcript cannot confuse a WARP verifier index with
/// some other preprocessing protocol's commitment.
const WARP_VK_COMMIT_TAG: &[u8] = b"argus:warp:vk:v1";

impl<F, P, C, MT> VerifierKeyCommitment for WARPVerifierKey<F, P, C, MT>
where
    F: Field,
    P: BundledPESAT<F>,
    C: LinearCode<F> + Clone,
    MT: Config,
{
    fn committed_index(&self) -> CommittedIndexBytes {
        // v1: canonical bytes of the verifier-visible dimensions only. CY24
        // §32.7.1 prescribes binding to a Merkle commitment of the encoded
        // verifier-index oracles (matrix roots); add that once WARP carries
        // those oracles in the verifier key.
        let mut out = Vec::with_capacity(WARP_VK_COMMIT_TAG.len() + 3 * 8);
        out.extend_from_slice(WARP_VK_COMMIT_TAG);
        out.extend_from_slice(&(self.m as u64).to_le_bytes());
        out.extend_from_slice(&(self.n as u64).to_le_bytes());
        out.extend_from_slice(&(self.k as u64).to_le_bytes());
        CommittedIndexBytes::new(out)
    }
}

// -----------------------------------------------------------------------
// WARPReduction: the full IOR as a single PreprocessingInteractiveReduction
// -----------------------------------------------------------------------

pub struct WARPReduction<F, P, C, MT> {
    _phantom: PhantomData<(F, P, C, MT)>,
}

impl<F, P, C, MT> WARPReduction<F, P, C, MT> {
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<F, P, C, MT> Default for WARPReduction<F, P, C, MT> {
    fn default() -> Self {
        Self::new()
    }
}

/// Security-relevant WARP parameters derived from a concrete index.
///
/// Every field is fixed once the static problem description (matrices,
/// dimensions, code, OOD/shift counts) is fixed, so these are index-derived,
/// not per-claim. The instance-derived security params are empty under the
/// current analysis.
#[derive(Clone, Debug)]
pub struct WARPSecurityParams {
    /// Number of twin-sumcheck folding rounds (= log2 of total instance count l).
    pub log_l: usize,
    /// Number of batching-sumcheck rounds (= log2 of codeword length n).
    pub log_n: usize,
    /// log2 of the number of R1CS constraints M.
    pub log_m: usize,
    /// Reed-Solomon codeword length n.
    pub n: usize,
    /// Reed-Solomon message length (dimension) k.
    pub k: usize,
    /// Approximate bit-length of the field size: |F| ≈ 2^field_bits.
    pub field_bits: u32,
    /// Number of OOD samples s (from `WARPConfig.s`).
    pub ood_samples: usize,
    /// Number of shift queries t (from `WARPConfig.t`).
    pub shift_queries: usize,
}

/// Worst-case/adaptive WARP bound. For now this mirrors the concrete parameter
/// shape, with each field interpreted as a maximum over the instance family.
pub type WARPSecurityBound = WARPSecurityParams;

impl<F, P, C, MT> ProtocolCore for WARPReduction<F, P, C, MT>
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
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        ia_core::pad_protocol_id(b"argus::warp::reduction")
    }
}

impl<F, P, C, MT> ReductionCore for WARPReduction<F, P, C, MT>
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
    type SourceInstance = WARPInstance<F, MT>;
    type SourceWitness = WARPWitness<F, MT>;
    type TargetInstance = DeciderInstance<F, MT>;
    type TargetWitness = DeciderWitness<F, MT>;
}

impl<F, P, C, MT> PreprocessingCore for WARPReduction<F, P, C, MT>
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
    type Index = WARPIndex<F, P, C, MT>;
    type ProverKey = WARPProverKey<F, P, C, MT>;
    type VerifierKey = WARPVerifierKey<F, P, C, MT>;

    fn index(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
        let pk = WARPProverKey {
            warp: ix.warp.clone(),
            m: ix.m,
            n: ix.n,
            k: ix.k,
        };
        let vk = WARPVerifierKey {
            warp: ix.warp.clone(),
            m: ix.m,
            n: ix.n,
            k: ix.k,
        };
        (pk, vk)
    }
}

impl<F, P, C, MT> PreprocessingInteractiveReduction for WARPReduction<F, P, C, MT>
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
    fn prove<Ch: ProverChannel>(
        &self,
        ch: &mut Ch,
        pk: &Self::ProverKey,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (DeciderInstance<F, MT>, DeciderWitness<F, MT>) {
        let warp = &pk.warp;
        // WARP::prove_with_channel still takes the (P, M, N, k) tuple. Build
        // it from the prover key.
        let pk_tuple = (warp.p.clone(), pk.m, pk.n, pk.k);

        let (acc_instance, acc_witness, _proof_data) = warp
            .prove_with_channel(
                ch,
                &pk_tuple,
                &instance.instances,
                &witness.witnesses,
                &instance.acc_instances,
                &witness.acc_witnesses,
            )
            .expect("honest prover must not fail");

        let target_instance = DeciderInstance { acc_instance };
        (target_instance, acc_witness)
    }

    fn verify<Ch: VerifierChannel>(
        &self,
        ch: &mut Ch,
        vk: &Self::VerifierKey,
        _instance: &Self::SourceInstance,
    ) -> VerificationResult<DeciderInstance<F, MT>> {
        let warp = &vk.warp;
        let dims = (vk.m, vk.n, vk.k);

        let result = warp
            .verify_reduction_transcript(ch, dims)
            .map_err(|_| ia_core::VerificationError)?;

        Ok(DeciderInstance {
            acc_instance: result.target,
        })
    }
}

impl<F, P, C, MT> PreprocessingReductionSecurity for WARPReduction<F, P, C, MT>
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
    type IndexParams = WARPSecurityParams;
    type IndexBound = WARPSecurityBound;
    // Instance-derived security is empty under the current analysis: every
    // soundness term is a function of dimensions / code params / OOD/shift
    // counts, all index-derived.
    type SourceParams = ();
    type SourceBound = ();
    type TargetBound = ();

    fn index_security_params(&self, ix: &Self::Index) -> Self::IndexParams {
        let warp = &ix.warp;
        let n = warp.code.code_len();
        WARPSecurityParams {
            log_l: log2(warp.config.l) as usize,
            log_n: log2(n) as usize,
            log_m: log2(ix.m) as usize,
            n,
            k: warp.code.message_len(),
            field_bits: F::MODULUS_BIT_SIZE,
            ood_samples: warp.config.s,
            shift_queries: warp.config.t,
        }
    }

    fn index_bound_for_index_params(&self, params: &Self::IndexParams) -> Self::IndexBound {
        params.clone()
    }

    fn source_security_params(
        &self,
        _ix_params: &Self::IndexParams,
        _instance: &Self::SourceInstance,
    ) -> Self::SourceParams {
    }

    fn source_bound_for_source_params(
        &self,
        _ix_params: &Self::IndexParams,
        _params: &Self::SourceParams,
    ) -> Self::SourceBound {
    }

    fn target_bound_for_source_params(
        &self,
        _ix_params: &Self::IndexParams,
        _params: &Self::SourceParams,
    ) -> Self::TargetBound {
    }

    fn target_bound_for_source_bound(
        &self,
        _ix_bound: &Self::IndexBound,
        _bound: &Self::SourceBound,
    ) -> Self::TargetBound {
    }

    fn profile_for_source_params(
        &self,
        ix_params: &Self::IndexParams,
        _source_params: &Self::SourceParams,
    ) -> SecurityProfile {
        warp_security_profile(ix_params)
    }

    fn profile_for_source_bound(
        &self,
        ix_bound: &Self::IndexBound,
        _source_bound: &Self::SourceBound,
    ) -> SecurityProfile {
        warp_security_profile(ix_bound)
    }
}

fn warp_security_profile(params: &WARPSecurityParams) -> SecurityProfile {
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

    let field_inv = 2_f64.powi(-(params.field_bits as i32));

    // Reed-Solomon code-specific bounds.
    // δ = 1 − k/n (relative minimum distance).
    let delta = 1.0 - params.k as f64 / params.n as f64;
    // |Λ(C, δ)| ≤ n (conservative; TODO: tighten via Johnson bound).
    let list_size = params.n as f64;
    // err_PG(C, 2, δ) ≤ 3 · n² / |F|  (BCIKS20, degree 2 for quadratic R1CS, eprint §6.2).
    let err_pg = 3.0 * (params.n as f64).powi(2) * field_inv;
    let ell = (1usize << params.log_l) as f64;

    // Twin sumcheck degree = 1 + max(log_n + 1, log_m + 2).
    let twin_deg = 1 + (params.log_n + 1).max(params.log_m + 2);

    // Twin sumcheck RBR bounds: round j (0-indexed) adds Schwartz–Zippel + errPG.
    let twin_rbr: Vec<SecurityErrorBound> = (0..params.log_l)
        .map(|j| {
            let sz = (twin_deg as f64) * field_inv;
            let pg = (ell / (1u64 << j) as f64) * err_pg;
            SecurityErrorBound::new(move |_t| sz + pg)
        })
        .collect();

    // Batching sumcheck RBR bounds: degree 2 per round.
    let batch_rbr: Vec<SecurityErrorBound> = (0..params.log_n)
        .map(|_| SecurityErrorBound::new(move |_t| 2.0 * field_inv))
        .collect();

    let mut rbr = twin_rbr;
    rbr.extend(batch_rbr);

    // One-time (non-SR) commitment-phase terms.
    // OOD + shift-sampling (§7): |Λ|² · log_n / |F| + (1 − δ)^shift_queries
    let log_n_f = params.log_n as f64;
    let ood_term = list_size * list_size * log_n_f * field_inv;
    let shift_term = (1.0 - delta).powi(params.shift_queries as i32);
    // PESAT → code reduction (§5.2): |Λ| · log_M / |F|
    let log_m_f = params.log_m as f64;
    let pesat_term = list_size * log_m_f * field_inv;

    let plain_error = SecurityErrorBound::new(move |_t| ood_term + shift_term + pesat_term);

    SecurityProfile {
        plain_soundness_error: plain_error,
        rbr_soundness_errors: rbr.clone(),
        rbr_knowledge_soundness_errors: rbr,
        hvzk_error: SecurityErrorBound::zero(),
        // Each round squeezes one field element as a challenge.
        verifier_challenge_lengths: vec![1; params.log_l + params.log_n],
    }
}

// -----------------------------------------------------------------------
// WARPDeciderIA: the decider as an PreprocessingInteractiveArgument
//
// The decider has no prover-side preprocessing of its own (`ProverKey =
// ()`), but it reads warp.code / merkle params / p.evaluate_bundled from
// the verifier key. Index and verifier key are the same shapes as the
// reduction's, so a composed `ReducedArgument<WARPReduction, WARPDeciderIA>`
// can take an `(WARPIndex, WARPIndex)` pair.
// -----------------------------------------------------------------------

pub struct WARPDeciderIA<F, P, C, MT>(pub PhantomData<(F, P, C, MT)>);

impl<F, P, C, MT> Default for WARPDeciderIA<F, P, C, MT> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<F, P, C, MT> ProtocolCore for WARPDeciderIA<F, P, C, MT>
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
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        ia_core::pad_protocol_id(b"argus::warp::decider")
    }
}

impl<F, P, C, MT> ArgumentCore for WARPDeciderIA<F, P, C, MT>
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
    type Instance = DeciderInstance<F, MT>;
    type Witness = DeciderWitness<F, MT>;
}

impl<F, P, C, MT> PreprocessingCore for WARPDeciderIA<F, P, C, MT>
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
    type Index = WARPIndex<F, P, C, MT>;
    type ProverKey = ();
    type VerifierKey = WARPVerifierKey<F, P, C, MT>;

    fn index(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
        let vk = WARPVerifierKey {
            warp: ix.warp.clone(),
            m: ix.m,
            n: ix.n,
            k: ix.k,
        };
        ((), vk)
    }
}

impl<F, P, C, MT> PreprocessingInteractiveArgument for WARPDeciderIA<F, P, C, MT>
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
    fn prove<Ch: ProverChannel>(
        &self,
        ch: &mut Ch,
        _: &Self::ProverKey,
        _instance: &Self::Instance,
        witness: &Self::Witness,
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
        vk: &Self::VerifierKey,
        instance: &Self::Instance,
    ) -> VerificationResult<()> {
        let warp = &vk.warp;
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

impl<F, P, C, MT> PreprocessingArgumentSecurity for WARPDeciderIA<F, P, C, MT>
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
    type IndexParams = ();
    type IndexBound = ();
    type InstanceParams = ();
    type InstanceBound = ();

    fn index_security_params(&self, _ix: &Self::Index) -> Self::IndexParams {}

    fn index_bound_for_index_params(&self, _params: &Self::IndexParams) -> Self::IndexBound {}

    fn instance_security_params(
        &self,
        _ix_params: &Self::IndexParams,
        _instance: &Self::Instance,
    ) -> Self::InstanceParams {
    }

    fn instance_bound_for_instance_params(
        &self,
        _ix_params: &Self::IndexParams,
        _params: &Self::InstanceParams,
    ) -> Self::InstanceBound {
    }

    fn profile_for_instance_params(
        &self,
        _ix_params: &Self::IndexParams,
        _instance_params: &Self::InstanceParams,
    ) -> SecurityProfile {
        decider_security_profile()
    }

    fn profile_for_instance_bound(
        &self,
        _ix_bound: &Self::IndexBound,
        _instance_bound: &Self::InstanceBound,
    ) -> SecurityProfile {
        decider_security_profile()
    }
}

fn decider_security_profile() -> SecurityProfile {
    // The decider is a deterministic local check (no challenges, no rounds).
    SecurityProfile {
        plain_soundness_error: SecurityErrorBound::zero(),
        rbr_soundness_errors: Vec::new(),
        rbr_knowledge_soundness_errors: Vec::new(),
        hvzk_error: SecurityErrorBound::zero(),
        verifier_challenge_lengths: Vec::new(),
    }
}

// -----------------------------------------------------------------------
// FullWARP = ReducedArgument<WARPReduction, WARPDeciderIA>  (IR . IA -> IA)
// -----------------------------------------------------------------------
//
// Both components are indexed, so `FullWARP` implements
// `PreprocessingInteractiveArgument` via the composition impl in
// `ia_core::indexed`. The composed `Index` is `(WARPIndex, WARPIndex)` —
// callers pass the same index twice for now. Folding into a single
// `WARPIndex` for the composed `FullWARP` is a future cleanup.

pub type FullWARP<F, P, C, MT> =
    ReducedArgument<WARPReduction<F, P, C, MT>, WARPDeciderIA<F, P, C, MT>>;
