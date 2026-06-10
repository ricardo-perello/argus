use std::marker::PhantomData;
use std::sync::Arc;

use ark_codes::traits::LinearCode;
use ark_crypto_primitives::merkle_tree::{Config, MerkleTree};
use ark_ff::{Field, PrimeField};
use ark_poly::{DenseMultilinearExtension, Polynomial};
use ark_serialize::CanonicalSerialize;
use ark_std::log2;

use ia_core::{
    CommittedIndex, CommittedIndexBytes, PreprocessingArgumentSecurity,
    PreprocessingInteractiveReductionProver, PreprocessingInteractiveReductionVerifier,
    PreprocessingReductionSecurity, ProverChannel, SecurityErrorBound, SecurityProfile,
    VerificationResult, VerifierChannel,
};

use crate::protocol::commitment::committed_index_for;
use crate::protocol::warp::{
    DeciderInstance, DeciderWitness, WarpIndex, WarpInstance, WarpProverKey, WarpStaticMaterial,
    WarpVerifierKey, WarpWitness,
};
use crate::protocol::WarpMerkle;
use crate::relations::r1cs::R1CSConstraints;
use crate::relations::BundledPESAT;
use crate::utils::poly::{eq_poly, Hypercube};

fn indexed_material<F, P, C, MT>(
    ix: &WarpIndex<F, P, C, MT>,
) -> Arc<WarpStaticMaterial<F, P, C, MT>>
where
    F: Field,
    P: Clone + BundledPESAT<F, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone,
    MT: WarpMerkle<F>,
{
    Arc::new(WarpStaticMaterial::new(
        ix.config.clone(),
        ix.code.clone(),
        ix.relation.clone(),
        ix.merkle_params.clone(),
    ))
}

fn prover_key<F, P, C, MT>(
    material: Arc<WarpStaticMaterial<F, P, C, MT>>,
) -> WarpProverKey<F, P, C, MT>
where
    F: Field,
    P: BundledPESAT<F, Constraints = R1CSConstraints<F>, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone + CanonicalSerialize,
    MT: WarpMerkle<F>,
{
    let commitment = committed_index_for(&material);
    WarpProverKey {
        material,
        commitment,
    }
}

fn verifier_key<F, P, C, MT>(
    material: Arc<WarpStaticMaterial<F, P, C, MT>>,
) -> WarpVerifierKey<F, P, C, MT>
where
    F: Field,
    P: BundledPESAT<F, Constraints = R1CSConstraints<F>, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone + CanonicalSerialize,
    MT: WarpMerkle<F>,
{
    let commitment = committed_index_for(&material);
    WarpVerifierKey {
        material,
        commitment,
    }
}

// Both keys cache the index commitment computed once at `preprocess` time, so
// `pk.committed_index() == vk.committed_index()` by construction and the compiled
// PNIA can derive the transcript digest from whichever key it is handed.
impl<F, P, C, MT> CommittedIndex for WarpVerifierKey<F, P, C, MT>
where
    F: Field,
    P: BundledPESAT<F>,
    C: LinearCode<F> + Clone,
    MT: Config,
{
    fn committed_index(&self) -> CommittedIndexBytes {
        self.commitment.clone()
    }
}

impl<F, P, C, MT> CommittedIndex for WarpProverKey<F, P, C, MT>
where
    F: Field,
    P: BundledPESAT<F>,
    C: LinearCode<F> + Clone,
    MT: Config,
{
    fn committed_index(&self) -> CommittedIndexBytes {
        self.commitment.clone()
    }
}

// -----------------------------------------------------------------------
// WarpReduction roles
// -----------------------------------------------------------------------

pub struct WarpReductionIndexer<F, P, C, MT> {
    _phantom: PhantomData<(F, P, C, MT)>,
}

impl<F, P, C, MT> WarpReductionIndexer<F, P, C, MT> {
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<F, P, C, MT> Default for WarpReductionIndexer<F, P, C, MT> {
    fn default() -> Self {
        Self::new()
    }
}

pub struct WarpReductionProver<F, P, C, MT>(PhantomData<(F, P, C, MT)>);

impl<F, P, C, MT> Default for WarpReductionProver<F, P, C, MT> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

pub struct WarpReductionVerifier<F, P, C, MT>(PhantomData<(F, P, C, MT)>);

impl<F, P, C, MT> Default for WarpReductionVerifier<F, P, C, MT> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

/// Security-relevant WARP parameters derived from a concrete index.
///
/// Every field is fixed once the static problem description (matrices,
/// dimensions, code, OOD/shift counts) is fixed, so these are index-derived,
/// not per-claim. The instance-derived security params are empty under the
/// current analysis.
#[derive(Clone, Debug)]
pub struct WarpSecurityParams {
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
    /// Number of OOD samples s (from `WarpConfig.s`).
    pub ood_samples: usize,
    /// Number of shift queries t (from `WarpConfig.t`).
    pub shift_queries: usize,
}

/// Worst-case/adaptive WARP bound. For now this mirrors the concrete parameter
/// shape, with each field interpreted as a maximum over the instance family.
pub type WarpSecurityBound = WarpSecurityParams;

ia_core::impl_preprocessing_reduction_indexer! {
    impl<F, P, C, MT> for WarpReductionIndexer<F, P, C, MT>
where
    F: Field
        + PrimeField
        + Send
        + Sync
        + spongefish::Encoding
        + spongefish::Decoding
        + ia_core::Deserialize,
    P: Clone + BundledPESAT<F, Constraints = R1CSConstraints<F>, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone + CanonicalSerialize,
    MT: WarpMerkle<F>,
{
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        ia_core::pad_protocol_id(b"argus::warp::reduction")
    }

    type SourceInstance = WarpInstance<F, MT>;
    type TargetInstance = DeciderInstance<F, MT>;
    type Index = WarpIndex<F, P, C, MT>;
    type ProverKey = WarpProverKey<F, P, C, MT>;
    type VerifierKey = WarpVerifierKey<F, P, C, MT>;

    fn preprocess(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
        let material = indexed_material(ix);
        (prover_key(material.clone()), verifier_key(material))
    }
}
}

ia_core::impl_preprocessing_reduction_prover! {
    impl<F, P, C, MT> for WarpReductionProver<F, P, C, MT>
where
    F: Field
        + PrimeField
        + Send
        + Sync
        + spongefish::Encoding
        + spongefish::Decoding
        + ia_core::Deserialize,
    P: Clone + BundledPESAT<F, Constraints = R1CSConstraints<F>, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone + CanonicalSerialize,
    MT: WarpMerkle<F>,
{
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        ia_core::pad_protocol_id(b"argus::warp::reduction")
    }

    type SourceInstance = WarpInstance<F, MT>;
    type TargetInstance = DeciderInstance<F, MT>;
    type SourceWitness = WarpWitness<F, MT>;
    type TargetWitness = DeciderWitness<F, MT>;
    type ProverKey = WarpProverKey<F, P, C, MT>;

    fn prove<Ch: ProverChannel<Unit = u8>>(
        &self,
        ch: &mut Ch,
        pk: &Self::ProverKey,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (DeciderInstance<F, MT>, DeciderWitness<F, MT>) {
        let (acc_instance, acc_witness, _proof_data) = pk
            .material
            .prove_with_channel(
                ch,
                pk,
                &instance.instances,
                &witness.witnesses,
                &instance.acc_instances,
                &witness.acc_witnesses,
            )
            .expect("honest prover must not fail");

        let target_instance = DeciderInstance { acc_instance };
        (target_instance, acc_witness)
    }
}
}

ia_core::impl_preprocessing_reduction_verifier! {
    impl<F, P, C, MT> for WarpReductionVerifier<F, P, C, MT>
where
    F: Field
        + PrimeField
        + Send
        + Sync
        + spongefish::Encoding
        + spongefish::Decoding
        + ia_core::Deserialize,
    P: Clone + BundledPESAT<F, Constraints = R1CSConstraints<F>, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone + CanonicalSerialize,
    MT: WarpMerkle<F>,
{
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        ia_core::pad_protocol_id(b"argus::warp::reduction")
    }

    type SourceInstance = WarpInstance<F, MT>;
    type TargetInstance = DeciderInstance<F, MT>;
    type VerifierKey = WarpVerifierKey<F, P, C, MT>;

    fn verify<Ch: VerifierChannel<Unit = u8>>(
        &self,
        ch: &mut Ch,
        vk: &Self::VerifierKey,
        instance: &Self::SourceInstance,
    ) -> VerificationResult<DeciderInstance<F, MT>> {
        let result = vk
            .material
            .verify_reduction_transcript(ch, vk, instance)
            .map_err(|_| ia_core::VerificationError)?;

        Ok(DeciderInstance {
            acc_instance: result.target,
        })
    }
}
}

impl<F, P, C, MT> PreprocessingReductionSecurity for WarpReductionIndexer<F, P, C, MT>
where
    F: Field
        + PrimeField
        + Send
        + Sync
        + spongefish::Encoding
        + spongefish::Decoding
        + ia_core::Deserialize,
    P: Clone + BundledPESAT<F, Constraints = R1CSConstraints<F>, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone + CanonicalSerialize,
    MT: WarpMerkle<F>,
{
    type IndexParams = WarpSecurityParams;
    type IndexBound = WarpSecurityBound;
    // Instance-derived security is empty under the current analysis: every
    // soundness term is a function of dimensions / code params / OOD/shift
    // counts, all index-derived.
    type SourceParams = ();
    type SourceBound = ();
    type TargetBound = ();

    fn index_security_params(&self, ix: &Self::Index) -> Self::IndexParams {
        let (m, _, _) = ix.relation.config();
        let n = ix.code.code_len();
        WarpSecurityParams {
            log_l: log2(ix.config.l) as usize,
            log_n: log2(n) as usize,
            log_m: log2(m) as usize,
            n,
            k: ix.code.message_len(),
            field_bits: F::MODULUS_BIT_SIZE,
            ood_samples: ix.config.s,
            shift_queries: ix.config.t,
        }
    }

    fn index_bound_for_index_params(&self, params: &Self::IndexParams) -> Self::IndexBound {
        params.clone()
    }

    fn offline_binding_error(&self, _ix_params: &Self::IndexParams) -> SecurityErrorBound {
        warp_offline_binding_error()
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

fn warp_security_profile(params: &WarpSecurityParams) -> SecurityProfile {
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
    // |Λ(C, δ)| ≤ n. This deliberately keeps the conservative bound until a
    // reviewed Johnson-bound analysis is available.
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

/// Offline index-binding error for WARP (CY24 §32.7 COS, §32.8.1).
///
/// **Currently zero.** WARP's verifier key holds the *full* index material and
/// re-derives the code/relation locally, so the
/// verifier is **non-succinct**:
/// - there is no committed encoded index `rt_0` for a prover to equivocate, so
///   the Merkle binding term `E1` is zero; and
/// - the 256-bit blake3 digest of the index (`committed_index_for`) is absorbed
///   purely for Fiat–Shamir domain separation. A digest collision is **not
///   load-bearing**: the verifier still runs the real material's algebraic
///   checks, so a colliding transcript cannot make a false statement pass. The
///   `rho_0 = f_0(i)` collision term `E2` is therefore moot — CY24 §32.7 fn. 3
///   notes `rho_0` may be omitted exactly when the verifier hashes the full
///   instance. Any residual transcript collision is already the online sponge
///   term `25 t^2 / |Sigma|^c`.
///
/// When WARP gains a **succinct/holographic** verifier index (a Merkle
/// commitment `rt_0` to the encoded index of length `l_0`, opened by the prover),
/// this turns on:
///
/// ```text
///   eps_offline(t) = (t + 2*l_0)^2 / 2^(lambda+1)   // E1: binding of rt_0
///                  +  t^2          / 2^(lambda+1)    // E2: collision in f_0
/// ```
///
/// with `l_0` = encoded-index length (`WarpSecurityParams::n`) and `lambda` the
/// commitment's collision resistance (256 for blake3). It is added once to the
/// NARG soundness and knowledge bounds, never to zero knowledge (§32.8.4).
fn warp_offline_binding_error() -> SecurityErrorBound {
    // Non-succinct verifier (holds the full index material): no offline
    // commitment to break. See the doc above for the term that activates once
    // WARP has a succinct/holographic verifier index.
    SecurityErrorBound::zero()
}

// -----------------------------------------------------------------------
// WarpDecider roles
// -----------------------------------------------------------------------

/// Lightweight prover-side decider key. It carries only the committed index so
/// the DSFS prover binds exactly the same bytes as the verifier key.
#[derive(Clone)]
pub struct WarpDeciderProverKey {
    commitment: CommittedIndexBytes,
}

impl CommittedIndex for WarpDeciderProverKey {
    fn committed_index(&self) -> CommittedIndexBytes {
        self.commitment.clone()
    }
}

pub struct WarpDeciderIndexer<F, P, C, MT>(pub PhantomData<(F, P, C, MT)>);

impl<F, P, C, MT> Default for WarpDeciderIndexer<F, P, C, MT> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

pub struct WarpDeciderProver<F, P, C, MT>(pub PhantomData<(F, P, C, MT)>);

impl<F, P, C, MT> Default for WarpDeciderProver<F, P, C, MT> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

pub struct WarpDeciderVerifier<F, P, C, MT>(pub PhantomData<(F, P, C, MT)>);

impl<F, P, C, MT> Default for WarpDeciderVerifier<F, P, C, MT> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

ia_core::impl_preprocessing_argument_indexer! {
    impl<F, P, C, MT> for WarpDeciderIndexer<F, P, C, MT>
where
    F: Field
        + PrimeField
        + Send
        + Sync
        + spongefish::Encoding
        + spongefish::Decoding
        + ia_core::Deserialize,
    P: Clone + BundledPESAT<F, Constraints = R1CSConstraints<F>, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone + CanonicalSerialize,
    MT: WarpMerkle<F>,
{
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        ia_core::pad_protocol_id(b"argus::warp::decider")
    }

    type Instance = DeciderInstance<F, MT>;
    type Index = WarpIndex<F, P, C, MT>;
    type ProverKey = WarpDeciderProverKey;
    type VerifierKey = WarpVerifierKey<F, P, C, MT>;

    fn preprocess(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
        let material = indexed_material(ix);
        let verifier_key = verifier_key(material);
        let prover_key = WarpDeciderProverKey {
            commitment: verifier_key.commitment.clone(),
        };
        (prover_key, verifier_key)
    }
}
}

ia_core::impl_preprocessing_argument_prover! {
    impl<F, P, C, MT> for WarpDeciderProver<F, P, C, MT>
where
    F: Field
        + PrimeField
        + Send
        + Sync
        + spongefish::Encoding
        + spongefish::Decoding
        + ia_core::Deserialize,
    P: Clone + BundledPESAT<F, Constraints = R1CSConstraints<F>, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone + CanonicalSerialize,
    MT: WarpMerkle<F>,
{
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        ia_core::pad_protocol_id(b"argus::warp::decider")
    }

    type Instance = DeciderInstance<F, MT>;
    type Witness = DeciderWitness<F, MT>;
    type ProverKey = WarpDeciderProverKey;

    fn prove<Ch: ProverChannel<Unit = u8>>(
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
}
}

ia_core::impl_preprocessing_argument_verifier! {
    impl<F, P, C, MT> for WarpDeciderVerifier<F, P, C, MT>
where
    F: Field
        + PrimeField
        + Send
        + Sync
        + spongefish::Encoding
        + spongefish::Decoding
        + ia_core::Deserialize,
    P: Clone + BundledPESAT<F, Constraints = R1CSConstraints<F>, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone + CanonicalSerialize,
    MT: WarpMerkle<F>,
{
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        ia_core::pad_protocol_id(b"argus::warp::decider")
    }

    type Instance = DeciderInstance<F, MT>;
    type VerifierKey = WarpVerifierKey<F, P, C, MT>;

    fn verify<Ch: VerifierChannel<Unit = u8>>(
        &self,
        ch: &mut Ch,
        vk: &Self::VerifierKey,
        instance: &Self::Instance,
    ) -> VerificationResult<()> {
        let material = &vk.material;
        let (rt, alpha, mu, beta, eta) = &instance.acc_instance;
        let n = material.code.code_len();
        let log_n = log2(n) as usize;

        let mut f = vec![F::default(); n];
        for val in f.iter_mut() {
            *val = ch.read_prover_message()?;
        }

        let k = material.config.p_conf.2;
        let mut w = vec![F::default(); k];
        for val in w.iter_mut() {
            *val = ch.read_prover_message()?;
        }

        let computed_mt = MerkleTree::<MT>::new(
            &material.merkle_params.leaf_hash,
            &material.merkle_params.two_to_one_hash,
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
        let computed_eta = material
            .relation
            .evaluate_bundled(&tau_zero_evader, &z)
            .map_err(|_| ia_core::VerificationError)?;
        if computed_eta != eta[0] {
            return Err(ia_core::VerificationError);
        }

        let computed_f = material.code.encode(&w);
        if f != computed_f {
            return Err(ia_core::VerificationError);
        }

        Ok(())
    }
}
}

impl<F, P, C, MT> PreprocessingArgumentSecurity for WarpDeciderIndexer<F, P, C, MT>
where
    F: Field
        + PrimeField
        + Send
        + Sync
        + spongefish::Encoding
        + spongefish::Decoding
        + ia_core::Deserialize,
    P: Clone + BundledPESAT<F, Constraints = R1CSConstraints<F>, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone + CanonicalSerialize,
    MT: WarpMerkle<F>,
{
    type IndexParams = ();
    type IndexBound = ();
    type InstanceParams = ();
    type InstanceBound = ();

    fn index_security_params(&self, _ix: &Self::Index) -> Self::IndexParams {}

    fn index_bound_for_index_params(&self, _params: &Self::IndexParams) -> Self::IndexBound {}

    fn offline_binding_error(&self, _ix_params: &Self::IndexParams) -> SecurityErrorBound {
        // The decider's verifier key holds the full index material and performs a
        // deterministic local check (no challenges, no rounds, no separate index
        // commitment a prover could equivocate). All index binding is accounted
        // by the reduction's `offline_binding_error`.
        SecurityErrorBound::zero()
    }

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
// FullWarp roles: first-class single-index WARP argument
// -----------------------------------------------------------------------

pub struct FullWarpIndexer<F, P, C, MT>(PhantomData<(F, P, C, MT)>);

impl<F, P, C, MT> Default for FullWarpIndexer<F, P, C, MT> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

pub struct FullWarpProver<F, P, C, MT> {
    reduction: WarpReductionProver<F, P, C, MT>,
    decider: WarpDeciderProver<F, P, C, MT>,
}

impl<F, P, C, MT> FullWarpProver<F, P, C, MT> {
    pub fn new(
        reduction: WarpReductionProver<F, P, C, MT>,
        decider: WarpDeciderProver<F, P, C, MT>,
    ) -> Self {
        Self { reduction, decider }
    }
}

impl<F, P, C, MT> Default for FullWarpProver<F, P, C, MT> {
    fn default() -> Self {
        Self::new(WarpReductionProver::default(), WarpDeciderProver::default())
    }
}

pub struct FullWarpVerifier<F, P, C, MT> {
    reduction: WarpReductionVerifier<F, P, C, MT>,
    decider: WarpDeciderVerifier<F, P, C, MT>,
}

impl<F, P, C, MT> FullWarpVerifier<F, P, C, MT> {
    pub fn new(
        reduction: WarpReductionVerifier<F, P, C, MT>,
        decider: WarpDeciderVerifier<F, P, C, MT>,
    ) -> Self {
        Self { reduction, decider }
    }
}

impl<F, P, C, MT> Default for FullWarpVerifier<F, P, C, MT> {
    fn default() -> Self {
        Self::new(
            WarpReductionVerifier::default(),
            WarpDeciderVerifier::default(),
        )
    }
}

ia_core::impl_preprocessing_argument_indexer! {
    impl<F, P, C, MT> for FullWarpIndexer<F, P, C, MT>
where
    F: Field
        + PrimeField
        + Send
        + Sync
        + spongefish::Encoding
        + spongefish::Decoding
        + ia_core::Deserialize,
    P: Clone + BundledPESAT<F, Constraints = R1CSConstraints<F>, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone + CanonicalSerialize,
    MT: WarpMerkle<F>,
{
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        ia_core::pad_protocol_id(b"argus::warp::full")
    }

    type Instance = WarpInstance<F, MT>;
    type Index = WarpIndex<F, P, C, MT>;
    type ProverKey = WarpProverKey<F, P, C, MT>;
    type VerifierKey = WarpVerifierKey<F, P, C, MT>;

    fn preprocess(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
        let material = indexed_material(ix);
        (prover_key(material.clone()), verifier_key(material))
    }
}
}

ia_core::impl_preprocessing_argument_prover! {
    impl<F, P, C, MT> for FullWarpProver<F, P, C, MT>
where
    F: Field
        + PrimeField
        + Send
        + Sync
        + spongefish::Encoding
        + spongefish::Decoding
        + ia_core::Deserialize,
    P: Clone + BundledPESAT<F, Constraints = R1CSConstraints<F>, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone + CanonicalSerialize,
    MT: WarpMerkle<F>,
{
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        ia_core::pad_protocol_id(b"argus::warp::full")
    }

    type Instance = WarpInstance<F, MT>;
    type Witness = WarpWitness<F, MT>;
    type ProverKey = WarpProverKey<F, P, C, MT>;

    fn prove<Ch: ProverChannel<Unit = u8>>(
        &self,
        ch: &mut Ch,
        pk: &Self::ProverKey,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) {
        let (target_instance, target_witness) = self.reduction.prove(ch, pk, instance, witness);
        let decider_key = WarpDeciderProverKey {
            commitment: pk.commitment.clone(),
        };
        self.decider
            .prove(ch, &decider_key, &target_instance, &target_witness);
    }
}
}

ia_core::impl_preprocessing_argument_verifier! {
    impl<F, P, C, MT> for FullWarpVerifier<F, P, C, MT>
where
    F: Field
        + PrimeField
        + Send
        + Sync
        + spongefish::Encoding
        + spongefish::Decoding
        + ia_core::Deserialize,
    P: Clone + BundledPESAT<F, Constraints = R1CSConstraints<F>, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone + CanonicalSerialize,
    MT: WarpMerkle<F>,
{
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        ia_core::pad_protocol_id(b"argus::warp::full")
    }

    type Instance = WarpInstance<F, MT>;
    type VerifierKey = WarpVerifierKey<F, P, C, MT>;

    fn verify<Ch: VerifierChannel<Unit = u8>>(
        &self,
        ch: &mut Ch,
        vk: &Self::VerifierKey,
        instance: &Self::Instance,
    ) -> VerificationResult<()> {
        let target_instance = self.reduction.verify(ch, vk, instance)?;
        self.decider.verify(ch, vk, &target_instance)
    }
}
}
