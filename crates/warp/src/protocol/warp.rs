use ark_codes::traits::LinearCode;
use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{Config, MerkleTree, Path},
};
use ark_ff::{Field, PrimeField};
use ark_poly::{
    univariate::DensePolynomial, DenseMultilinearExtension, DenseUVPolynomial,
    MultilinearExtension, Polynomial,
};
use ark_std::log2;
use ia_core::{CommittedIndexBytes, ProverChannel, VerifierChannel};

use crate::config::WarpConfig;
use crate::crypto::merkle::{build_codeword_leaves, compute_auth_paths};
use crate::errors::{WARPProverError, WARPVerifierError};
use crate::protocol::{batching_sumcheck, twin_sumcheck, WarpMerkle};
use crate::relations::r1cs::R1CSConstraints;
use crate::relations::BundledPESAT;
use crate::types::{AccumulatorInstances, AccumulatorWitnesses};
use crate::utils::poly::{compute_hypercube_eq_evals, eq_poly, eq_poly_non_binary};
use crate::utils::{
    binary_field_elements_to_usize, byte_to_binary_field_array, concat_slices, scale_and_sum,
    BoolResult, FastMap,
};

// -----------------------------------------------------------------------
// Static preprocessing material
// -----------------------------------------------------------------------

pub struct WarpMerkleParams<MT: Config> {
    pub leaf_hash: <MT::LeafHash as CRHScheme>::Parameters,
    pub two_to_one_hash: <MT::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
}

impl<MT> Clone for WarpMerkleParams<MT>
where
    MT: Config,
    <MT::LeafHash as CRHScheme>::Parameters: Clone,
    <MT::TwoToOneHash as TwoToOneCRHScheme>::Parameters: Clone,
{
    fn clone(&self) -> Self {
        Self {
            leaf_hash: self.leaf_hash.clone(),
            two_to_one_hash: self.two_to_one_hash.clone(),
        }
    }
}

impl<MT: Config> WarpMerkleParams<MT> {
    pub fn new(
        leaf_hash: <MT::LeafHash as CRHScheme>::Parameters,
        two_to_one_hash: <MT::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
    ) -> Self {
        Self {
            leaf_hash,
            two_to_one_hash,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WarpDimensions {
    pub m: usize,
    pub n: usize,
    pub k: usize,
}

impl WarpDimensions {
    pub fn new(m: usize, n: usize, k: usize) -> Self {
        Self { m, n, k }
    }

    pub fn as_tuple(self) -> (usize, usize, usize) {
        (self.m, self.n, self.k)
    }
}

/// Static problem description for WARP preprocessing.
///
/// This is intentionally an internal execution object rather than the public
/// verifier key. The public preprocessing boundary is `WarpIndex` -> keys;
/// DSFS binds the verifier-side material through `WarpVerifierKey`.
pub(crate) struct WarpStaticMaterial<
    F: Field,
    P: BundledPESAT<F>,
    C: LinearCode<F> + Clone,
    MT: Config,
> {
    pub config: WarpConfig<F, P>,
    pub code: C,
    pub relation: P,
    pub merkle_params: WarpMerkleParams<MT>,
}

impl<
        F: Field,
        P: Clone + BundledPESAT<F, Config = (usize, usize, usize)>,
        C: LinearCode<F> + Clone,
        MT: WarpMerkle<F>,
    > WarpStaticMaterial<F, P, C, MT>
{
    pub fn new(
        config: WarpConfig<F, P>,
        code: C,
        relation: P,
        merkle_params: WarpMerkleParams<MT>,
    ) -> Self {
        Self {
            config,
            code,
            relation,
            merkle_params,
        }
    }
}

// -----------------------------------------------------------------------
// Indexed-relation split: WarpIndex / WarpProverKey / WarpVerifierKey
//
// `WarpIndex` is the static problem description. `WarpReductionIndexer::preprocess`
// derives a (prover key, verifier key) pair from it. The verifier key carries
// an internally-derived commitment so its material and commitment cannot be
// provided independently.
// -----------------------------------------------------------------------

pub struct WarpIndex<F: Field, P: BundledPESAT<F>, C: LinearCode<F> + Clone, MT: Config> {
    pub config: WarpConfig<F, P>,
    pub relation: P,
    pub code: C,
    pub merkle_params: WarpMerkleParams<MT>,
}

impl<F, P, C, MT> WarpIndex<F, P, C, MT>
where
    F: Field,
    P: BundledPESAT<F>,
    C: LinearCode<F> + Clone,
    MT: Config,
{
    pub fn new(
        config: WarpConfig<F, P>,
        relation: P,
        code: C,
        merkle_params: WarpMerkleParams<MT>,
    ) -> Self {
        Self {
            config,
            relation,
            code,
            merkle_params,
        }
    }
}

#[derive(Clone)]
pub struct WarpProverKey<F: Field, P: BundledPESAT<F>, C: LinearCode<F> + Clone, MT: Config> {
    pub(crate) material: std::sync::Arc<WarpStaticMaterial<F, P, C, MT>>,
    pub(crate) commitment: CommittedIndexBytes,
}

impl<
        F: Field,
        P: BundledPESAT<F, Config = (usize, usize, usize)>,
        C: LinearCode<F> + Clone,
        MT: Config,
    > WarpProverKey<F, P, C, MT>
{
    /// Problem dimensions `(m, n, k)`, derived from the indexed relation.
    pub fn dimensions(&self) -> WarpDimensions {
        let (m, n, k) = self.material.relation.config();
        WarpDimensions::new(m, n, k)
    }
}

#[derive(Clone)]
pub struct WarpVerifierKey<F: Field, P: BundledPESAT<F>, C: LinearCode<F> + Clone, MT: Config> {
    pub(crate) material: std::sync::Arc<WarpStaticMaterial<F, P, C, MT>>,
    pub(crate) commitment: CommittedIndexBytes,
}

impl<
        F: Field,
        P: BundledPESAT<F, Config = (usize, usize, usize)>,
        C: LinearCode<F> + Clone,
        MT: Config,
    > WarpVerifierKey<F, P, C, MT>
{
    /// Problem dimensions `(m, n, k)`, derived from the indexed relation.
    pub fn dimensions(&self) -> WarpDimensions {
        let (m, n, k) = self.material.relation.config();
        WarpDimensions::new(m, n, k)
    }
}

// -----------------------------------------------------------------------
// Per-claim instance / witness for the WarpReduction preprocessing surface.
// -----------------------------------------------------------------------

pub struct WarpInstance<F: Field, MT: Config> {
    pub instances: Vec<Vec<F>>,
    pub acc_instances: AccumulatorInstances<F, MT>,
}

pub struct WarpWitness<F: Field, MT: Config> {
    pub witnesses: Vec<Vec<F>>,
    pub acc_witnesses: AccumulatorWitnesses<F, MT>,
}

// -----------------------------------------------------------------------
// Decider instance/witness (target of WarpReduction, input of WarpDecider).
// The decider reads the static WARP description from its verifier key, not
// from the instance, so DeciderInstance drops the `warp` and `pk` fields.
// -----------------------------------------------------------------------

pub struct DeciderInstance<F: Field, MT: Config> {
    pub acc_instance: AccumulatorInstances<F, MT>,
}

pub type DeciderWitness<F, MT> = AccumulatorWitnesses<F, MT>;

// -----------------------------------------------------------------------
// Encoding impls for DSFS domain separation
// -----------------------------------------------------------------------

impl<F, MT> spongefish::Encoding for WarpInstance<F, MT>
where
    F: Field + spongefish::Encoding,
    MT: Config,
    MT::InnerDigest: AsRef<[u8]>,
{
    fn encode(&self) -> impl AsRef<[u8]> {
        // Dimensions (M, N, k) used to ride along here; they now live in the
        // committed verifier index and are absorbed by the preprocessing DSFS path
        // via `WarpVerifierKey::committed_index`.
        let mut buf = Vec::new();
        for inst in &self.instances {
            for x in inst {
                buf.extend_from_slice(x.encode().as_ref());
            }
        }
        let (roots, alphas, mus, (taus, xs), etas) = &self.acc_instances;
        for root in roots {
            buf.extend_from_slice(root.as_ref());
        }
        for alpha in alphas {
            for a in alpha {
                buf.extend_from_slice(a.encode().as_ref());
            }
        }
        for mu in mus {
            buf.extend_from_slice(mu.encode().as_ref());
        }
        for tau in taus {
            for t in tau {
                buf.extend_from_slice(t.encode().as_ref());
            }
        }
        for x in xs {
            for v in x {
                buf.extend_from_slice(v.encode().as_ref());
            }
        }
        for eta in etas {
            buf.extend_from_slice(eta.encode().as_ref());
        }
        buf
    }
}

/// Auxiliary result from `verify_reduction_transcript`.
pub struct ReductionTranscriptResult<F: Field, MT: Config> {
    pub target: AccumulatorInstances<F, MT>,
    pub rt_0: MT::InnerDigest,
    pub l2_roots: Vec<MT::InnerDigest>,
    pub shift_queries_indexes: Vec<usize>,
}

/// All proof data the verifier needs (sent out-of-band or embedded in instance).
pub struct WarpProofData<F: Field, MT: Config> {
    pub rt_0: MT::InnerDigest,
    pub mus: Vec<F>,
    pub nu_0: F,
    pub nus: Vec<F>,
    pub auth_0: Vec<Path<MT>>,
    pub auth: Vec<Vec<Path<MT>>>,
    pub shift_queries_answers: Vec<Vec<F>>,
}

// -----------------------------------------------------------------------
// Prover
// -----------------------------------------------------------------------

impl<
        F: Field + PrimeField + Send + Sync,
        P: Clone + BundledPESAT<F, Constraints = R1CSConstraints<F>, Config = (usize, usize, usize)>,
        C: LinearCode<F> + Clone,
        MT: WarpMerkle<F>,
    > WarpStaticMaterial<F, P, C, MT>
where
    F: spongefish::Encoding + spongefish::Decoding,
{
    /// Full WARP prover, sending all messages through the channel.
    #[allow(clippy::type_complexity)]
    pub fn prove_with_channel<Ch: ProverChannel<Unit = u8>>(
        &self,
        ch: &mut Ch,
        pk: &WarpProverKey<F, P, C, MT>,
        instances: &[Vec<F>],
        witnesses: &[Vec<F>],
        acc_instances: &AccumulatorInstances<F, MT>,
        acc_witnesses: &AccumulatorWitnesses<F, MT>,
    ) -> Result<
        (
            AccumulatorInstances<F, MT>,
            AccumulatorWitnesses<F, MT>,
            WarpProofData<F, MT>,
        ),
        WARPProverError,
    > {
        let (l1, l) = (self.config.l1, self.config.l);
        if instances.len() != l1 || witnesses.len() != l1 {
            return Err(WARPProverError::InvalidInputCount {
                expected: l1,
                instances: instances.len(),
                witnesses: witnesses.len(),
            });
        }
        if l == 0 || !l.is_power_of_two() || l1 > l {
            return Err(WARPProverError::InvalidConfiguration(
                "`l` must be a non-zero power of two and at least `l1`",
            ));
        }
        let _l2 = l - l1;

        // ---- Phase 1: Parsing ----
        #[allow(non_snake_case)]
        let (M, N, k) = pk.dimensions().as_tuple();
        if M == 0 || N == 0 || k > N || !M.is_power_of_two() {
            return Err(WARPProverError::InvalidConfiguration(
                "relation dimensions require non-zero, power-of-two `M` and `k <= N`",
            ));
        }
        #[allow(non_snake_case)]
        let (log_M, log_l) = (log2(M) as usize, log2(l) as usize);
        let n = self.code.code_len();
        if n == 0 || !n.is_power_of_two() {
            return Err(WARPProverError::InvalidConfiguration(
                "the code length must be a non-zero power of two",
            ));
        }
        let log_n = log2(n) as usize;

        // The source statement (l1 instances + accumulators) is public input:
        // DSFS binds it via `WarpInstance::encode()` before the first challenge,
        // so it is not also streamed as prover messages. The verifier reads it
        // from its own `instance` argument instead. (Construction 4.3: public
        // input is still fixed before the first challenge; this only removes a
        // redundant in-transcript copy of the statement.)

        // ---- Phase 2: PESAT Reduction ----
        let (codewords, leaves) = build_codeword_leaves(&self.code, witnesses, l1);
        let mus: Vec<F> = codewords.iter().map(|f| f[0]).collect();

        let td_0 = MerkleTree::<MT>::new(
            &self.merkle_params.leaf_hash,
            &self.merkle_params.two_to_one_hash,
            leaves.chunks_exact(l1).collect::<Vec<_>>(),
        )?;

        // absorb commitment (root as bytes)
        let root_bytes = td_0.root();
        self.send_digest(ch, &root_bytes);

        for mu in &mus {
            ch.send_prover_message(mu);
        }

        // squeeze tau_i for each l1 instance
        let mut taus = vec![vec![F::default(); log_M]; l1];
        for tau in taus.iter_mut() {
            for t in tau.iter_mut() {
                *t = ch.read_verifier_message();
            }
        }

        // ---- Phase 3: Constrained Code Accumulation ----
        let omega: F = ch.read_verifier_message();
        let mut tau = vec![F::default(); log_l];
        for t in tau.iter_mut() {
            *t = ch.read_verifier_message();
        }

        let tau_eq_evals = compute_hypercube_eq_evals(log_l, &tau);
        let alpha_vecs = concat_slices(&acc_instances.1, &vec![vec![F::zero(); log_n]; l1]);

        let z_vecs: Vec<Vec<F>> = acc_instances
            .3
             .1
            .iter()
            .zip(&acc_witnesses.2)
            .chain(instances.iter().zip(witnesses))
            .map(|(x, w)| concat_slices(x, w))
            .collect();

        let beta_vecs: Vec<Vec<F>> = acc_instances.3 .0.iter().cloned().chain(taus).collect();

        let mut evals = twin_sumcheck::Evals::new(
            concat_slices(&acc_witnesses.1, &codewords),
            z_vecs,
            alpha_vecs,
            beta_vecs,
            tau_eq_evals,
        );

        let n_coeffs = 2 + (log_n + 1).max(log_M + 2);
        let gamma = twin_sumcheck::prove(
            ch,
            &mut evals,
            self.relation.constraints(),
            omega,
            log_l,
            n_coeffs,
        );

        debug_assert_eq!(gamma.len(), log_l);

        // e. new oracle and target
        let (f, z, zeta_0, beta_tau) = evals.get_last_evals().ok_or(WARPProverError::EmptyEval)?;

        let beta_eq_evals: Vec<F> = (0..M).map(|i| eq_poly(&beta_tau, i)).collect();
        let eta = self
            .relation
            .evaluate_bundled(&beta_eq_evals, &z)
            .map_err(|_| WARPProverError::BundledEvaluation)?;

        let (x_part, w_part) = z.split_at(N - k);
        let beta = (vec![beta_tau.clone()], vec![x_part.to_vec()]);
        let f_hat = DenseMultilinearExtension::from_evaluations_slice(log_n, &f);
        let nu_0 = f_hat.fix_variables(&zeta_0)[0];

        // f. new commitment
        let td = MerkleTree::<MT>::new(
            &self.merkle_params.leaf_hash,
            &self.merkle_params.two_to_one_hash,
            f.chunks(1).collect::<Vec<_>>(),
        )?;

        // g. absorb new commitment and target
        self.send_digest(ch, &td.root());
        ch.send_prover_message(&eta);
        ch.send_prover_message(&nu_0);

        // h. OOD samples
        let n_ood_samples = self.config.s * log_n;
        let mut ood_samples = Vec::with_capacity(n_ood_samples);
        for _ in 0..n_ood_samples {
            let s: F = ch.read_verifier_message();
            ood_samples.push(s);
        }
        let ood_sample_chunks: Vec<&[F]> = ood_samples.chunks(log_n).collect();

        // i. OOD answers
        let ood_answers: Vec<F> = ood_sample_chunks
            .iter()
            .map(|ood_p| f_hat.fix_variables(ood_p)[0])
            .collect();

        for ans in &ood_answers {
            ch.send_prover_message(ans);
        }

        let mut zetas: Vec<&[F]> = vec![zeta_0.as_slice()];
        let mut nus = vec![nu_0];
        zetas.extend(&ood_sample_chunks);
        nus.extend(&ood_answers);

        // k. shift queries and zerocheck randomness
        let r = 1 + self.config.s + self.config.t;
        let log_r = log2(r) as usize;
        let n_shift_query_bytes = (self.config.t * log_n).div_ceil(8);

        let mut bytes_shift_queries = vec![0u8; n_shift_query_bytes];
        for b in bytes_shift_queries.iter_mut() {
            let byte_val: [u8; 1] = ch.read_verifier_message();
            *b = byte_val[0];
        }

        let mut xis = Vec::with_capacity(log_r);
        for _ in 0..log_r {
            let xi: F = ch.read_verifier_message();
            xis.push(xi);
        }

        let binary_shift_queries: Vec<F> = bytes_shift_queries
            .iter()
            .flat_map(byte_to_binary_field_array)
            .take(self.config.t * log_n)
            .collect();
        let binary_shift_query_chunks: Vec<&[F]> = binary_shift_queries.chunks(log_n).collect();

        let shift_queries_indexes: Vec<usize> = binary_shift_query_chunks
            .iter()
            .map(|vals| binary_field_elements_to_usize(vals))
            .collect();

        let mut all_zetas = zetas;
        for chunk in &binary_shift_query_chunks {
            all_zetas.push(chunk);
        }

        // l. batching sumcheck
        let xi_eq_evals: Vec<F> = (0..r).map(|i| eq_poly(&xis, i)).collect();

        let ood_evals_vec: Vec<Vec<F>> = (0..1 + self.config.s)
            .map(|i| {
                (0..n)
                    .map(|a| eq_poly(all_zetas[i], a) * xi_eq_evals[i])
                    .collect()
            })
            .collect();

        let id_non_0 = cbbz23(&all_zetas, &xi_eq_evals, self.config.s, r);

        let alpha = batching_sumcheck::prove(ch, &mut f.clone(), &ood_evals_vec, &id_non_0, log_n);

        // m. new target
        let mu_final = f_hat.fix_variables(&alpha)[0];

        // n. compute authentication paths
        let auth_0 = compute_auth_paths(&td_0, &shift_queries_indexes)?;

        let auth: Vec<Vec<Path<MT>>> = acc_witnesses
            .0
            .iter()
            .map(|td_acc| compute_auth_paths(td_acc, &shift_queries_indexes))
            .collect::<Result<Vec<_>, _>>()?;

        let all_codewords: Vec<&Vec<F>> = acc_witnesses.1.iter().chain(codewords.iter()).collect();

        let mut shift_queries_answers =
            vec![vec![F::default(); all_codewords.len()]; shift_queries_indexes.len()];
        for (i, idx) in shift_queries_indexes.iter().enumerate() {
            let answers: Vec<F> = all_codewords.iter().map(|f| f[*idx]).collect();
            shift_queries_answers[i] = answers;
        }

        // Send shift_queries_answers through the channel so the
        // IR verifier can read them and compute nu_{s+k}.
        for answers in &shift_queries_answers {
            for a in answers {
                ch.send_prover_message(a);
            }
        }

        let new_acc_instance = (
            vec![td.root()],
            vec![alpha],
            vec![mu_final],
            beta,
            vec![eta],
        );
        let new_acc_witness = (vec![td], vec![f], vec![w_part.to_vec()]);

        let proof_data = WarpProofData {
            rt_0: td_0.root(),
            mus,
            nu_0,
            nus,
            auth_0,
            auth,
            shift_queries_answers,
        };

        Ok((new_acc_instance, new_acc_witness, proof_data))
    }

    /// IOR verifier: reads the prover's transcript messages, performs the
    /// sumcheck checks, and **computes** the target `AccumulatorInstances`.
    ///
    /// The source statement is taken from the `instance` argument (public input,
    /// bound by DSFS via `WarpInstance::encode()`), not re-read from the
    /// transcript. Shift-query answers are read from the channel (the prover
    /// sends them after the batching sumcheck). Merkle auth-path verification is
    /// NOT performed here -- that belongs to the BCS oracle layer.
    ///
    /// Returns the target accumulator instance plus auxiliary data needed
    /// by the BCS oracle layer (source roots, shift query indexes).
    pub fn verify_reduction_transcript<Ch: VerifierChannel<Unit = u8>>(
        &self,
        ch: &mut Ch,
        vk: &WarpVerifierKey<F, P, C, MT>,
        instance: &WarpInstance<F, MT>,
    ) -> Result<ReductionTranscriptResult<F, MT>, WARPVerifierError>
    where
        F: ia_core::Deserialize,
    {
        let (l1, l) = (self.config.l1, self.config.l);
        let l2 = l - l1;

        #[allow(non_snake_case)]
        let (M, N, k) = vk.dimensions().as_tuple();
        #[allow(non_snake_case)]
        let (log_M, log_l) = (log2(M) as usize, log2(l) as usize);
        let n = self.code.code_len();
        let log_n = log2(n) as usize;

        // ---- Phase 1: take the statement from the public-input instance ----
        // The source statement is the verifier's own `instance` argument (bound
        // by DSFS as public input), not re-read from the transcript. Validate
        // its shape against the index dimensions.
        if instance.instances.len() != l1 || instance.instances.iter().any(|xs| xs.len() != N - k) {
            return Err(WARPVerifierError::SumcheckRound);
        }
        let l1_xs = instance.instances.clone();

        let (l2_roots, l2_alphas, l2_mus, l2_taus, l2_xs, l2_etas) = {
            let (roots, alphas, mus, (taus, xs), etas) = &instance.acc_instances;
            if roots.len() != l2 {
                return Err(WARPVerifierError::SumcheckRound);
            }
            (
                roots.clone(),
                alphas.clone(),
                mus.clone(),
                taus.clone(),
                xs.clone(),
                etas.clone(),
            )
        };

        // ---- Phase 2: Derive randomness ----
        let rt_0: MT::InnerDigest = self.read_digest(ch)?;
        let mut l1_mus = vec![F::default(); l1];
        for mu in l1_mus.iter_mut() {
            *mu = ch
                .read_prover_message()
                .map_err(|_| WARPVerifierError::SumcheckRound)?;
        }

        let mut l1_taus = vec![vec![F::default(); log_M]; l1];
        for l1_tau in l1_taus.iter_mut() {
            for t in l1_tau.iter_mut() {
                *t = ch.send_verifier_message();
            }
        }

        let omega: F = ch.send_verifier_message();
        let mut tau = vec![F::default(); log_l];
        for t in tau.iter_mut() {
            *t = ch.send_verifier_message();
        }

        // twin constraint sumcheck
        let n_coeffs = 2 + (log_n + 1).max(log_M + 2);
        let (gamma_sumcheck, coeffs_twinc_sumcheck) = twin_sumcheck::verify(ch, n_coeffs, log_l)
            .map_err(|_| WARPVerifierError::SumcheckRound)?;

        // read new commitment and target
        let td_root: MT::InnerDigest = self.read_digest(ch)?;
        let eta: F = ch
            .read_prover_message()
            .map_err(|_| WARPVerifierError::SumcheckRound)?;
        let nu_0: F = ch
            .read_prover_message()
            .map_err(|_| WARPVerifierError::SumcheckRound)?;
        let mut nus = vec![nu_0];

        // OOD samples
        let n_ood_samples = self.config.s * log_n;
        let mut ood_samples = vec![F::default(); n_ood_samples];
        for s in ood_samples.iter_mut() {
            *s = ch.send_verifier_message();
        }

        let mut ood_answers = vec![F::default(); self.config.s];
        for ans in ood_answers.iter_mut() {
            *ans = ch
                .read_prover_message()
                .map_err(|_| WARPVerifierError::SumcheckRound)?;
        }
        nus.extend(&ood_answers);

        // shift queries
        let r = 1 + self.config.s + self.config.t;
        let log_r = log2(r) as usize;
        let n_shift_query_bytes = (self.config.t * log_n).div_ceil(8);

        let mut bytes_shift_queries = vec![0u8; n_shift_query_bytes];
        for b in bytes_shift_queries.iter_mut() {
            let byte_val: [u8; 1] = ch.send_verifier_message();
            *b = byte_val[0];
        }

        let mut xi = vec![F::default(); log_r];
        for x in xi.iter_mut() {
            *x = ch.send_verifier_message();
        }

        // batching sumcheck
        let (alpha_sumcheck, sums_batching_sumcheck) =
            batching_sumcheck::verify::<F, Ch>(ch, log_n)
                .map_err(|_| WARPVerifierError::SumcheckRound)?;

        // ---- Read shift query answers from channel (sent by prover) ----
        let mut shift_queries_answers = vec![vec![F::default(); l]; self.config.t];
        for answers in shift_queries_answers.iter_mut() {
            for a in answers.iter_mut() {
                *a = ch
                    .read_prover_message()
                    .map_err(|_| WARPVerifierError::SumcheckRound)?;
            }
        }

        // ---- Derive values ----
        let alpha_vecs = concat_slices(&l2_alphas, &vec![vec![F::zero(); log_n]; l1]);
        let gamma_eq_evals = compute_hypercube_eq_evals(log_l, &gamma_sumcheck);
        let zeta_0 = scale_and_sum(&alpha_vecs, &gamma_eq_evals);

        let binary_shift_queries: Vec<F> = bytes_shift_queries
            .iter()
            .flat_map(byte_to_binary_field_array)
            .take(self.config.t * log_n)
            .collect();
        let binary_shift_query_chunks: Vec<&[F]> = binary_shift_queries.chunks(log_n).collect();

        let shift_queries_indexes: Vec<usize> = binary_shift_query_chunks
            .iter()
            .map(|vals| binary_field_elements_to_usize(vals))
            .collect();

        let mut nu_s_t = vec![F::default(); self.config.t];
        for (i, v_jk) in shift_queries_answers.iter().enumerate() {
            let res = v_jk
                .iter()
                .zip(&gamma_eq_evals)
                .fold(F::zero(), |acc, (v, eq)| acc + *eq * *v);
            nu_s_t[i] = res;
        }
        nus.extend(nu_s_t);

        let tau_eq_evals = compute_hypercube_eq_evals(log_l, &tau);
        let etas_all = concat_slices(&l2_etas, &vec![F::zero(); l1]);

        let sigma_1 = tau_eq_evals
            .into_iter()
            .zip(l2_mus.into_iter().chain(l1_mus.to_vec()).zip(etas_all))
            .fold(F::zero(), |acc, (eq_tau, (mu, eta_val))| {
                acc + eq_tau * (mu + omega * eta_val)
            });

        let xi_eq_evals = compute_hypercube_eq_evals(log_r, &xi);
        let sigma_2 = xi_eq_evals
            .iter()
            .zip(&nus)
            .fold(F::zero(), |acc, (xi_eq, nu)| acc + *xi_eq * nu);

        // ---- Sumcheck round verification ----
        (coeffs_twinc_sumcheck.len() == log_l).ok_or_err(WARPVerifierError::NumSumcheckRounds)?;

        let mut target_1 = sigma_1;
        for (coeffs, gamma) in coeffs_twinc_sumcheck.into_iter().zip(&gamma_sumcheck) {
            let h = DensePolynomial::from_coefficients_vec(coeffs);
            (h.evaluate(&F::one()) + h.evaluate(&F::zero()) == target_1)
                .ok_or_err(WARPVerifierError::SumcheckRound)?;
            target_1 = h.evaluate(gamma);
        }

        (sums_batching_sumcheck.len() == log_n).ok_or_err(WARPVerifierError::NumSumcheckRounds)?;
        let mut target_2 = sigma_2;
        for ([sum_00, sum_11, sum_0110], alpha) in
            sums_batching_sumcheck.into_iter().zip(&alpha_sumcheck)
        {
            (sum_00 + sum_11 == target_2).ok_or_err(WARPVerifierError::SumcheckRound)?;
            target_2 = (target_2 - sum_0110) * alpha.square()
                + sum_00 * (F::one() - alpha.double())
                + sum_0110 * alpha;
        }

        // ---- Twin sumcheck target equation ----
        (eq_poly_non_binary(&tau, &gamma_sumcheck) * (nus[0] + omega * eta) == target_1)
            .ok_or_err(WARPVerifierError::SumcheckTarget)?;

        // ---- Compute target AccumulatorInstances ----
        let ood_sample_chunks: Vec<&[F]> = ood_samples.chunks(log_n).collect();

        let mut zeta_eqs = vec![eq_poly_non_binary(&zeta_0, &alpha_sumcheck)];
        zeta_eqs.extend(
            ood_sample_chunks
                .iter()
                .map(|zeta| eq_poly_non_binary(zeta, &alpha_sumcheck)),
        );
        zeta_eqs.extend(
            binary_shift_query_chunks
                .iter()
                .map(|zeta| eq_poly_non_binary(zeta, &alpha_sumcheck)),
        );
        (zeta_eqs.len() == r).ok_or_err(WARPVerifierError::NumShiftQueries)?;

        let k_sum = zeta_eqs
            .into_iter()
            .zip(xi_eq_evals)
            .fold(F::zero(), |acc, (a, b)| acc + a * b);
        let mu_target = target_2 * k_sum.inverse().ok_or(WARPVerifierError::SumcheckTarget)?;

        let betas: Vec<Vec<F>> = l2_taus
            .into_iter()
            .chain(l1_taus)
            .zip(l2_xs.into_iter().chain(l1_xs))
            .map(|(tau_vec, x_vec)| concat_slices(&tau_vec, &x_vec))
            .collect();
        let beta_flat = scale_and_sum(&betas, &gamma_eq_evals);
        let log_m = log_M;
        let (beta_tau_part, beta_x_part) = beta_flat.split_at(log_m);

        Ok(ReductionTranscriptResult {
            target: (
                vec![td_root],
                vec![alpha_sumcheck],
                vec![mu_target],
                (vec![beta_tau_part.to_vec()], vec![beta_x_part.to_vec()]),
                vec![eta],
            ),
            rt_0,
            l2_roots,
            shift_queries_indexes,
        })
    }

    // ---- Helper methods for digest serialization ----

    fn send_digest<Ch: ProverChannel<Unit = u8>>(&self, ch: &mut Ch, digest: &MT::InnerDigest) {
        let bytes = digest.as_ref();
        for &b in bytes {
            ch.send_prover_message(&[b]);
        }
    }

    fn read_digest<Ch: VerifierChannel<Unit = u8>>(
        &self,
        ch: &mut Ch,
    ) -> Result<MT::InnerDigest, WARPVerifierError>
    where
        F: ia_core::Deserialize,
    {
        let mut digest = [0u8; 32];
        for b in digest.iter_mut() {
            let byte: [u8; 1] = ch
                .read_prover_message()
                .map_err(|_| WARPVerifierError::SumcheckRound)?;
            *b = byte[0];
        }
        Ok(digest.into())
    }
}

/// CBBZ23 optimization from hyperplonk: compute non-zero identity evaluations
/// for shift query zetas.
fn cbbz23<F: Field>(zetas: &[&[F]], xi_eq_evals: &[F], s: usize, r: usize) -> FastMap<F> {
    let mut id_non_0_eval_sums = FastMap::default();
    for i in 1 + s..r {
        let a = zetas[i]
            .iter()
            .enumerate()
            .filter_map(|(j, bit)| bit.is_one().then_some(1 << j))
            .sum::<usize>();
        *id_non_0_eval_sums.entry(a).or_insert(F::zero()) += &xi_eq_evals[i];
    }
    id_non_0_eval_sums
}
