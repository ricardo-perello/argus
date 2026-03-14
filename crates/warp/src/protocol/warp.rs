use std::marker::PhantomData;

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
use ia_core::{ProverChannel, VerifierChannel};

use crate::config::WARPConfig;
use crate::crypto::merkle::{build_codeword_leaves, compute_auth_paths};
use crate::errors::{WARPDeciderError, WARPError, WARPVerifierError};
use crate::protocol::{batching_sumcheck, twin_sumcheck};
use crate::relations::r1cs::R1CSConstraints;
use crate::relations::BundledPESAT;
use crate::types::{AccumulatorInstances, AccumulatorWitnesses};
use crate::utils::poly::{compute_hypercube_eq_evals, eq_poly, eq_poly_non_binary, Hypercube};
use crate::utils::{
    binary_field_elements_to_usize, byte_to_binary_field_array, concat_slices, scale_and_sum,
    BoolResult, FastMap,
};

// -----------------------------------------------------------------------
// WARP struct: holds static protocol parameters
// -----------------------------------------------------------------------

pub struct WARP<F: Field, P: BundledPESAT<F>, C: LinearCode<F> + Clone, MT: Config> {
    _f: PhantomData<F>,
    pub config: WARPConfig<F, P>,
    pub code: C,
    pub p: P,
    pub mt_leaf_hash_params: <MT::LeafHash as CRHScheme>::Parameters,
    pub mt_two_to_one_hash_params: <MT::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
}

impl<
        F: Field,
        P: Clone + BundledPESAT<F, Config = (usize, usize, usize)>,
        C: LinearCode<F> + Clone,
        MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
    > WARP<F, P, C, MT>
{
    pub fn new(
        config: WARPConfig<F, P>,
        code: C,
        p: P,
        mt_leaf_hash_params: <MT::LeafHash as CRHScheme>::Parameters,
        mt_two_to_one_hash_params: <MT::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
    ) -> Self {
        Self {
            _f: PhantomData,
            config,
            code,
            p,
            mt_leaf_hash_params,
            mt_two_to_one_hash_params,
        }
    }
}

// -----------------------------------------------------------------------
// Instance / Witness types for the WARP InteractiveReduction
// -----------------------------------------------------------------------

pub struct WARPInstance<F: Field, P: BundledPESAT<F>, C: LinearCode<F> + Clone, MT: Config> {
    pub warp: std::sync::Arc<WARP<F, P, C, MT>>,
    pub pk: (P, usize, usize, usize),
    pub instances: Vec<Vec<F>>,
    pub acc_instances: AccumulatorInstances<F, MT>,
}

pub struct WARPWitness<F: Field, MT: Config> {
    pub witnesses: Vec<Vec<F>>,
    pub acc_witnesses: AccumulatorWitnesses<F, MT>,
}

pub struct WARPTargetInstance<F: Field, MT: Config> {
    pub acc_instance: AccumulatorInstances<F, MT>,
    pub proof: WARPProofData<F, MT>,
}

pub struct WARPTargetWitness<F: Field, MT: Config> {
    pub acc_witness: AccumulatorWitnesses<F, MT>,
}

/// All proof data the verifier needs (sent out-of-band or embedded in instance).
pub struct WARPProofData<F: Field, MT: Config> {
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
        MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
    > WARP<F, P, C, MT>
where
    F: spongefish::Encoding + spongefish::Decoding,
{
    /// Full WARP prover, sending all messages through the channel.
    #[allow(clippy::type_complexity)]
    pub fn prove_with_channel<Ch: ProverChannel>(
        &self,
        ch: &mut Ch,
        pk: &(P, usize, usize, usize),
        instances: &[Vec<F>],
        witnesses: &[Vec<F>],
        acc_instances: &AccumulatorInstances<F, MT>,
        acc_witnesses: &AccumulatorWitnesses<F, MT>,
    ) -> Result<
        (
            AccumulatorInstances<F, MT>,
            AccumulatorWitnesses<F, MT>,
            WARPProofData<F, MT>,
        ),
        crate::errors::WARPProverError,
    >
    where
        Ch: ProverChannel,
    {
        debug_assert!(instances.len() > 1);
        debug_assert_eq!(witnesses.len(), instances.len());

        let (l1, l) = (self.config.l1, self.config.l);
        let _l2 = l - l1;
        debug_assert!(l.is_power_of_two());

        // ---- Phase 1: Parsing ----
        #[allow(non_snake_case)]
        let (M, N, k) = (pk.1, pk.2, pk.3);
        #[allow(non_snake_case)]
        let (log_M, log_l) = (log2(M) as usize, log2(l) as usize);
        let n = self.code.code_len();
        let log_n = log2(n) as usize;

        // absorb instances
        for inst in instances {
            for x in inst {
                ch.send_prover_message(x);
            }
        }

        // absorb accumulated instances
        self.absorb_acc_instances_prover(ch, acc_instances);

        // ---- Phase 2: PESAT Reduction ----
        let (codewords, leaves) = build_codeword_leaves(&self.code, witnesses, l1);
        let mus: Vec<F> = codewords.iter().map(|f| f[0]).collect();

        let td_0 = MerkleTree::<MT>::new(
            &self.mt_leaf_hash_params,
            &self.mt_two_to_one_hash_params,
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

        let beta_vecs: Vec<Vec<F>> = acc_instances
            .3
             .0
            .iter()
            .cloned()
            .chain(taus.into_iter())
            .collect();

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
            self.p.constraints(),
            omega,
            log_l,
            n_coeffs,
        );

        debug_assert_eq!(gamma.len(), log_l);

        // e. new oracle and target
        let (f, z, zeta_0, beta_tau) = evals.get_last_evals().unwrap();

        let beta_eq_evals: Vec<F> = (0..M).map(|i| eq_poly(&beta_tau, i)).collect();
        let eta = self
            .p
            .evaluate_bundled(&beta_eq_evals, &z)
            .expect("bundled evaluation failed");

        let (x_part, w_part) = z.split_at(N - k);
        let beta = (vec![beta_tau.clone()], vec![x_part.to_vec()]);
        let f_hat = DenseMultilinearExtension::from_evaluations_slice(log_n, &f);
        let nu_0 = f_hat.fix_variables(&zeta_0)[0];

        // f. new commitment
        let td = MerkleTree::<MT>::new(
            &self.mt_leaf_hash_params,
            &self.mt_two_to_one_hash_params,
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
        let binary_shift_query_chunks: Vec<&[F]> =
            binary_shift_queries.chunks(log_n).collect();

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

        let alpha = batching_sumcheck::prove(
            ch,
            &mut f.clone(),
            &ood_evals_vec,
            &id_non_0,
            log_n,
        );

        // m. new target
        let mu_final = f_hat.fix_variables(&alpha)[0];

        // n. compute authentication paths
        let auth_0 = compute_auth_paths(&td_0, &shift_queries_indexes)?;

        let auth: Vec<Vec<Path<MT>>> = acc_witnesses
            .0
            .iter()
            .map(|td_acc| compute_auth_paths(td_acc, &shift_queries_indexes))
            .collect::<Result<Vec<_>, _>>()?;

        let all_codewords: Vec<&Vec<F>> = acc_witnesses
            .1
            .iter()
            .chain(codewords.iter())
            .collect();

        let mut shift_queries_answers =
            vec![vec![F::default(); all_codewords.len()]; shift_queries_indexes.len()];
        for (i, idx) in shift_queries_indexes.iter().enumerate() {
            let answers: Vec<F> = all_codewords.iter().map(|f| f[*idx]).collect();
            shift_queries_answers[i] = answers;
        }

        let new_acc_instance = (
            vec![td.root()],
            vec![alpha],
            vec![mu_final],
            beta,
            vec![eta],
        );
        let new_acc_witness = (vec![td], vec![f], vec![w_part.to_vec()]);

        let proof_data = WARPProofData {
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

    /// Full WARP verifier, reading all messages from the channel.
    pub fn verify_with_channel<'a, Ch: VerifierChannel>(
        &self,
        ch: &mut Ch,
        vk: (usize, usize, usize),
        acc_instance: &AccumulatorInstances<F, MT>,
        proof: &WARPProofData<F, MT>,
    ) -> Result<(), WARPVerifierError>
    where
        F: ia_core::Deserialize,
    {
        let (l1, l) = (self.config.l1, self.config.l);
        let l2 = l - l1;

        #[allow(non_snake_case)]
        let (M, N, k) = vk;
        #[allow(non_snake_case)]
        let (log_M, log_l) = (log2(M) as usize, log2(l) as usize);
        let n = self.code.code_len();
        let log_n = log2(n) as usize;

        // ---- Phase 1: Parse statement ----
        let mut l1_xs = vec![vec![F::default(); N - k]; l1];
        for inst in l1_xs.iter_mut() {
            for x in inst.iter_mut() {
                *x = ch.read_prover_message().map_err(|_| WARPVerifierError::SumcheckRound)?;
            }
        }

        // read accumulated instances
        let (l2_roots, l2_alphas, l2_mus, l2_taus, l2_xs, l2_etas) =
            self.read_acc_instances_verifier(ch, l2, log_n, log_M, N - k)?;

        // ---- Phase 2: Derive randomness ----
        let rt_0: MT::InnerDigest = self.read_digest(ch)?;
        let mut l1_mus = vec![F::default(); l1];
        for mu in l1_mus.iter_mut() {
            *mu = ch.read_prover_message().map_err(|_| WARPVerifierError::SumcheckRound)?;
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
        let (gamma_sumcheck, coeffs_twinc_sumcheck) =
            twin_sumcheck::verify(ch, n_coeffs, log_l)
                .map_err(|_| WARPVerifierError::SumcheckRound)?;

        // read new commitment and target
        let _td_root: MT::InnerDigest = self.read_digest(ch)?;
        let eta: F = ch.read_prover_message().map_err(|_| WARPVerifierError::SumcheckRound)?;
        let nu_0: F = ch.read_prover_message().map_err(|_| WARPVerifierError::SumcheckRound)?;
        let mut nus = vec![nu_0];

        // OOD samples
        let n_ood_samples = self.config.s * log_n;
        let mut ood_samples = vec![F::default(); n_ood_samples];
        for s in ood_samples.iter_mut() {
            *s = ch.send_verifier_message();
        }

        // OOD answers
        let mut ood_answers = vec![F::default(); self.config.s];
        for ans in ood_answers.iter_mut() {
            *ans = ch.read_prover_message().map_err(|_| WARPVerifierError::SumcheckRound)?;
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
            batching_sumcheck::verify(ch, log_n)
                .map_err(|_| WARPVerifierError::SumcheckRound)?;

        // ---- Phase 3: Derive values ----
        let alpha_vecs = concat_slices(&l2_alphas, &vec![vec![F::zero(); log_n]; l1]);
        let gamma_eq_evals = compute_hypercube_eq_evals(log_l, &gamma_sumcheck);
        let zeta_0 = scale_and_sum(&alpha_vecs, &gamma_eq_evals);

        let binary_shift_queries: Vec<F> = bytes_shift_queries
            .iter()
            .flat_map(byte_to_binary_field_array)
            .take(self.config.t * log_n)
            .collect();
        let binary_shift_query_chunks: Vec<&[F]> =
            binary_shift_queries.chunks(log_n).collect();

        let shift_queries_indexes: Vec<usize> = binary_shift_query_chunks
            .iter()
            .map(|vals| binary_field_elements_to_usize(vals))
            .collect();

        // compute nu_{s+k} from shift query answers
        let mut nu_s_t = vec![F::default(); self.config.t];
        for (i, v_jk) in proof.shift_queries_answers.iter().enumerate() {
            let res = v_jk
                .iter()
                .zip(&gamma_eq_evals)
                .fold(F::zero(), |acc, (v, eq)| acc + *eq * *v);
            nu_s_t[i] = res;
        }
        nus.extend(nu_s_t);

        // sigma_1 and sigma_2
        let tau_eq_evals = compute_hypercube_eq_evals(log_l, &tau);
        let etas = concat_slices(&l2_etas, &vec![F::zero(); l1]);

        let sigma_1 = tau_eq_evals
            .into_iter()
            .zip(l2_mus.into_iter().chain(l1_mus.to_vec()).zip(etas))
            .fold(F::zero(), |acc, (eq_tau, (mu, eta_val))| {
                acc + eq_tau * (mu + omega * eta_val)
            });

        let xi_eq_evals = compute_hypercube_eq_evals(log_r, &xi);
        let sigma_2 = xi_eq_evals
            .iter()
            .zip(&nus)
            .fold(F::zero(), |acc, (xi_eq, nu)| acc + *xi_eq * nu);

        // ---- Phase 4: Decision ----
        // a. new code evaluation point
        (acc_instance.1[0] == alpha_sumcheck)
            .ok_or_err(WARPVerifierError::CodeEvaluationPoint)?;

        // b. new circuit evaluation point
        let betas: Vec<Vec<F>> = l2_taus
            .into_iter()
            .chain(l1_taus)
            .zip(l2_xs.into_iter().chain(l1_xs))
            .map(|(tau_vec, x_vec)| concat_slices(&tau_vec, &x_vec))
            .collect();
        let beta = scale_and_sum(&betas, &gamma_eq_evals);
        let expected_beta = concat_slices(&acc_instance.3 .0[0], &acc_instance.3 .1[0]);
        (expected_beta == beta).ok_or_err(WARPVerifierError::CircuitEvaluationPoint)?;

        // c. check auth paths
        (proof.shift_queries_answers.len() == self.config.t)
            .ok_or_err(WARPVerifierError::NumShiftQueries)?;

        for (i, path) in proof.auth_0.iter().enumerate() {
            (path.leaf_index == shift_queries_indexes[i])
                .ok_or_err(WARPVerifierError::ShiftQueryIndex)?;
            let is_valid = path
                .verify(
                    &self.mt_leaf_hash_params,
                    &self.mt_two_to_one_hash_params,
                    &rt_0,
                    &proof.shift_queries_answers[i][l2..],
                )
                .map_err(|_| WARPVerifierError::ShiftQuery)?;
            is_valid.ok_or_err(WARPVerifierError::ShiftQuery)?;
        }

        (proof.auth.len() == l2).ok_or_err(WARPVerifierError::NumL2Instances)?;
        for (i, paths) in proof.auth.iter().enumerate() {
            (paths.len() == self.config.t)
                .ok_or_err(WARPVerifierError::NumShiftQueries)?;
            let root = &l2_roots[i];
            for (j, path) in paths.iter().enumerate() {
                (path.leaf_index == shift_queries_indexes[j])
                    .ok_or_err(WARPVerifierError::ShiftQueryIndex)?;
                let is_valid = path
                    .verify(
                        &self.mt_leaf_hash_params,
                        &self.mt_two_to_one_hash_params,
                        root,
                        [proof.shift_queries_answers[j][i]],
                    )
                    .map_err(|_| WARPVerifierError::ShiftQuery)?;
                is_valid.ok_or_err(WARPVerifierError::ShiftQuery)?;
            }
        }

        // d. sumcheck decisions
        // twin constraints sumcheck
        (coeffs_twinc_sumcheck.len() == log_l)
            .ok_or_err(WARPVerifierError::NumSumcheckRounds)?;

        let mut target_1 = sigma_1;
        for (coeffs, gamma) in coeffs_twinc_sumcheck.into_iter().zip(&gamma_sumcheck) {
            let h = DensePolynomial::from_coefficients_vec(coeffs);
            (h.evaluate(&F::one()) + h.evaluate(&F::zero()) == target_1)
                .ok_or_err(WARPVerifierError::SumcheckRound)?;
            target_1 = h.evaluate(gamma);
        }

        // multilinear batching sumcheck
        (sums_batching_sumcheck.len() == log_n)
            .ok_or_err(WARPVerifierError::NumSumcheckRounds)?;
        let mut target_2 = sigma_2;
        for ([sum_00, sum_11, sum_0110], alpha) in
            sums_batching_sumcheck.into_iter().zip(&alpha_sumcheck)
        {
            (sum_00 + sum_11 == target_2).ok_or_err(WARPVerifierError::SumcheckRound)?;
            target_2 = (target_2 - sum_0110) * alpha.square()
                + sum_00 * (F::one() - alpha.double())
                + sum_0110 * alpha;
        }

        // e. new target decision
        let ood_sample_chunks: Vec<&[F]> = ood_samples.chunks(log_n).collect();

        (eq_poly_non_binary(&tau, &gamma_sumcheck) * (nus[0] + omega * eta) == target_1)
            .ok_or_err(WARPVerifierError::SumcheckTarget)?;

        let mut zeta_eqs = vec![eq_poly_non_binary(&zeta_0, &alpha_sumcheck)];
        zeta_eqs.extend(
            ood_sample_chunks
                .iter()
                .map(|zeta| eq_poly_non_binary(zeta, &alpha_sumcheck))
                .collect::<Vec<F>>(),
        );
        zeta_eqs.extend(
            binary_shift_query_chunks
                .iter()
                .map(|zeta| eq_poly_non_binary(zeta, &alpha_sumcheck))
                .collect::<Vec<F>>(),
        );
        (zeta_eqs.len() == r).ok_or_err(WARPVerifierError::NumShiftQueries)?;

        (acc_instance.2[0]
            * zeta_eqs
                .into_iter()
                .zip(xi_eq_evals)
                .fold(F::zero(), |acc, (a, b)| acc + a * b)
            == target_2)
            .ok_or_err(WARPVerifierError::SumcheckTarget)?;

        Ok(())
    }

    /// Decider: checks the final accumulator instance/witness consistency.
    pub fn decide(
        &self,
        acc_witness: &AccumulatorWitnesses<F, MT>,
        acc_instance: &AccumulatorInstances<F, MT>,
    ) -> Result<(), WARPError>
    where
        F: PrimeField,
    {
        let (mt, f, w) = acc_witness;
        let (rt, alpha, mu, beta, eta) = acc_instance;

        let computed_mt = MerkleTree::<MT>::new(
            &self.mt_leaf_hash_params,
            &self.mt_two_to_one_hash_params,
            f[0].chunks(1).collect::<Vec<_>>(),
        )?;
        (rt[0] == computed_mt.root()).ok_or_err(WARPDeciderError::MerkleRoot)?;
        (mt[0].root() == computed_mt.root()).ok_or_err(WARPDeciderError::MerkleTrapDoor)?;
        (mt[0].leaf_nodes == computed_mt.leaf_nodes).ok_or_err(WARPDeciderError::MerkleRoot)?;

        let f_hat = DenseMultilinearExtension::from_evaluations_slice(
            log2(self.code.code_len()) as usize,
            &f[0],
        );
        (f_hat.evaluate(&alpha[0]) == mu[0])
            .ok_or_err(WARPDeciderError::MLExtensionEvaluation)?;

        let tau_val = &beta.0[0];
        let tau_zero_evader: Vec<F> = Hypercube::new(tau_val.len())
            .map(|index| eq_poly(tau_val, index))
            .collect();

        let mut z = beta.1[0].clone();
        z.extend(w[0].clone());
        let computed_eta = self.p.evaluate_bundled(&tau_zero_evader, &z).unwrap();
        (computed_eta == eta[0]).ok_or_err(WARPDeciderError::BundledEvaluation)?;

        let computed_f = self.code.encode(&w[0]);
        (f[0] == computed_f).ok_or_err(WARPDeciderError::EncodedWitness)?;

        Ok(())
    }

    // ---- Helper methods for digest serialization ----

    fn send_digest<Ch: ProverChannel>(&self, ch: &mut Ch, digest: &MT::InnerDigest) {
        let bytes = digest.as_ref();
        for &b in bytes {
            ch.send_prover_message(&[b]);
        }
    }

    fn read_digest<Ch: VerifierChannel>(
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

    fn absorb_acc_instances_prover<Ch: ProverChannel>(
        &self,
        ch: &mut Ch,
        acc: &AccumulatorInstances<F, MT>,
    ) {
        for digest in &acc.0 {
            self.send_digest(ch, digest);
        }
        for alpha in &acc.1 {
            for a in alpha {
                ch.send_prover_message(a);
            }
        }
        for mu in &acc.2 {
            ch.send_prover_message(mu);
        }
        for tau in &acc.3 .0 {
            for t in tau {
                ch.send_prover_message(t);
            }
        }
        for x in &acc.3 .1 {
            for v in x {
                ch.send_prover_message(v);
            }
        }
        for eta in &acc.4 {
            ch.send_prover_message(eta);
        }
    }

    #[allow(clippy::type_complexity)]
    fn read_acc_instances_verifier<Ch: VerifierChannel>(
        &self,
        ch: &mut Ch,
        l2: usize,
        log_n: usize,
        log_m: usize,
        instance_len: usize,
    ) -> Result<
        (
            Vec<MT::InnerDigest>,
            Vec<Vec<F>>,
            Vec<F>,
            Vec<Vec<F>>,
            Vec<Vec<F>>,
            Vec<F>,
        ),
        WARPVerifierError,
    >
    where
        F: ia_core::Deserialize,
    {
        if l2 == 0 {
            return Ok((vec![], vec![], vec![], vec![], vec![], vec![]));
        }

        let mut roots = Vec::with_capacity(l2);
        for _ in 0..l2 {
            roots.push(self.read_digest(ch)?);
        }

        let mut alphas = vec![vec![F::default(); log_n]; l2];
        for alpha in alphas.iter_mut() {
            for a in alpha.iter_mut() {
                *a = ch
                    .read_prover_message()
                    .map_err(|_| WARPVerifierError::SumcheckRound)?;
            }
        }

        let mut mus = vec![F::default(); l2];
        for mu in mus.iter_mut() {
            *mu = ch
                .read_prover_message()
                .map_err(|_| WARPVerifierError::SumcheckRound)?;
        }

        let mut taus = vec![vec![F::default(); log_m]; l2];
        for tau in taus.iter_mut() {
            for t in tau.iter_mut() {
                *t = ch
                    .read_prover_message()
                    .map_err(|_| WARPVerifierError::SumcheckRound)?;
            }
        }

        let mut xs = vec![vec![F::default(); instance_len]; l2];
        for x in xs.iter_mut() {
            for v in x.iter_mut() {
                *v = ch
                    .read_prover_message()
                    .map_err(|_| WARPVerifierError::SumcheckRound)?;
            }
        }

        let mut etas = vec![F::default(); l2];
        for e in etas.iter_mut() {
            *e = ch
                .read_prover_message()
                .map_err(|_| WARPVerifierError::SumcheckRound)?;
        }

        Ok((roots, alphas, mus, taus, xs, etas))
    }
}

/// CBBZ23 optimization from hyperplonk: compute non-zero identity evaluations
/// for shift query zetas.
fn cbbz23<F: Field>(
    zetas: &[&[F]],
    xi_eq_evals: &[F],
    s: usize,
    r: usize,
) -> FastMap<F> {
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
