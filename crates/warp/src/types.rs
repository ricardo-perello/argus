use ark_codes::traits::LinearCode;
use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{Config, MerkleTree, Path},
};
use ark_ff::Field;

use crate::config::WARPConfig;
use crate::relations::r1cs::R1CSConstraints;
use crate::relations::BundledPESAT;

// -----------------------------------------------------------------------
// Source instance for the full WARP pipeline (ParseAndCommit's input)
// -----------------------------------------------------------------------

pub struct WARPSourceInstance<F: Field, P: BundledPESAT<F>, C: LinearCode<F>, MT: Config> {
    pub config: WARPConfig<F, P>,
    pub code: C,
    pub p: P,
    pub mt_leaf_hash_params: <MT::LeafHash as CRHScheme>::Parameters,
    pub mt_two_to_one_hash_params: <MT::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
    pub instances: Vec<Vec<F>>,
    pub acc_instances: AccumulatorInstances<F, MT>,
}

pub struct WARPSourceWitness<F: Field, MT: Config> {
    pub witnesses: Vec<Vec<F>>,
    pub acc_witnesses: AccumulatorWitnesses<F, MT>,
}

// -----------------------------------------------------------------------
// Accumulator types (same as the original warp)
// -----------------------------------------------------------------------

/// (roots, alphas, mus, (taus, xs), etas)
pub type AccumulatorInstances<F, MT> = (
    Vec<<MT as Config>::InnerDigest>,
    Vec<Vec<F>>,
    Vec<F>,
    (Vec<Vec<F>>, Vec<Vec<F>>),
    Vec<F>,
);

/// (merkle_trees, codewords, witness_parts)
pub type AccumulatorWitnesses<F, MT> = (Vec<MerkleTree<MT>>, Vec<Vec<F>>, Vec<Vec<F>>);

// -----------------------------------------------------------------------
// ParseAndCommit -> TwinSumcheck interface
// -----------------------------------------------------------------------

pub struct ParseCommitOutput<F: Field, MT: Config> {
    pub td_0: MerkleTree<MT>,
    pub codewords: Vec<Vec<F>>,
    pub mus: Vec<F>,
    pub taus: Vec<Vec<F>>,
    pub omega: F,
    pub tau: Vec<F>,
    // carried forward from source
    pub r1cs_constraints: R1CSConstraints<F>,
    pub acc_instances: AccumulatorInstances<F, MT>,
    pub instances: Vec<Vec<F>>,
    pub log_m: usize,
    pub log_n: usize,
    pub log_l: usize,
    // full config parameters
    pub m: usize,
    pub n_code: usize,
    pub n_vars: usize,
    pub k: usize,
    pub s: usize,
    pub t: usize,
}

pub struct ParseCommitWitnessOutput<F: Field, MT: Config> {
    pub evals_u: Vec<Vec<F>>,
    pub evals_z: Vec<Vec<F>>,
    pub evals_a: Vec<Vec<F>>,
    pub evals_b: Vec<Vec<F>>,
    pub evals_tau: Vec<F>,
    // carried
    pub witnesses: Vec<Vec<F>>,
    pub acc_witnesses: AccumulatorWitnesses<F, MT>,
    pub codewords: Vec<Vec<F>>,
}

// -----------------------------------------------------------------------
// TwinSumcheck -> CommitAndSample interface
// -----------------------------------------------------------------------

pub struct TwinSumcheckOutput<F: Field, MT: Config> {
    pub gamma_challenges: Vec<F>,
    pub f: Vec<F>,
    pub z: Vec<F>,
    pub zeta_0: Vec<F>,
    pub beta_tau: Vec<F>,
    // carried from ParseCommit
    pub td_0: MerkleTree<MT>,
    pub codewords: Vec<Vec<F>>,
    pub r1cs_constraints: R1CSConstraints<F>,
    pub acc_instances: AccumulatorInstances<F, MT>,
    pub instances: Vec<Vec<F>>,
    pub omega: F,
    pub log_m: usize,
    pub log_n: usize,
    pub log_l: usize,
    pub m: usize,
    pub n_code: usize,
    pub n_vars: usize,
    pub k: usize,
    pub s: usize,
    pub t: usize,
}

pub struct TwinSumcheckWitnessOutput<F: Field, MT: Config> {
    pub witnesses: Vec<Vec<F>>,
    pub acc_witnesses: AccumulatorWitnesses<F, MT>,
    pub codewords: Vec<Vec<F>>,
}

// -----------------------------------------------------------------------
// CommitAndSample -> BatchingSumcheck interface
// -----------------------------------------------------------------------

pub struct CommitSampleOutput<F: Field, MT: Config> {
    pub td: MerkleTree<MT>,
    pub td_0: MerkleTree<MT>,
    pub eta: F,
    pub nu_0: F,
    pub ood_samples: Vec<F>,
    pub ood_answers: Vec<F>,
    pub shift_query_bytes: Vec<u8>,
    pub xis: Vec<F>,
    pub zeta_0: Vec<F>,
    pub f: Vec<F>,
    // carried
    pub gamma_challenges: Vec<F>,
    pub codewords: Vec<Vec<F>>,
    pub r1cs_constraints: R1CSConstraints<F>,
    pub acc_instances: AccumulatorInstances<F, MT>,
    pub instances: Vec<Vec<F>>,
    pub omega: F,
    pub beta_tau: Vec<F>,
    pub z: Vec<F>,
    pub log_m: usize,
    pub log_n: usize,
    pub log_l: usize,
    pub m: usize,
    pub n_code: usize,
    pub n_vars: usize,
    pub k: usize,
    pub s: usize,
    pub t: usize,
}

pub struct CommitSampleWitnessOutput<F: Field, MT: Config> {
    pub witnesses: Vec<Vec<F>>,
    pub acc_witnesses: AccumulatorWitnesses<F, MT>,
    pub codewords: Vec<Vec<F>>,
    pub w: Vec<F>,
}

// -----------------------------------------------------------------------
// BatchingSumcheck -> WARPDecider interface
// -----------------------------------------------------------------------

pub struct BatchingSumcheckOutput<F: Field, MT: Config> {
    pub alpha_challenges: Vec<F>,
    pub mu_final: F,
    // everything needed for the decider
    pub td: MerkleTree<MT>,
    pub td_0: MerkleTree<MT>,
    pub f: Vec<F>,
    pub eta: F,
    pub beta_tau: Vec<F>,
    pub z: Vec<F>,
    // all proof components needed by verifier
    pub gamma_challenges: Vec<F>,
    pub codewords: Vec<Vec<F>>,
    pub acc_instances: AccumulatorInstances<F, MT>,
    pub instances: Vec<Vec<F>>,
    pub omega: F,
    pub zeta_0: Vec<F>,
    pub nu_0: F,
    pub nus: Vec<F>,
    pub ood_samples: Vec<F>,
    pub shift_query_bytes: Vec<u8>,
    pub xis: Vec<F>,
    pub r1cs_constraints: R1CSConstraints<F>,
    pub log_m: usize,
    pub log_n: usize,
    pub log_l: usize,
    pub m: usize,
    pub n_code: usize,
    pub n_vars: usize,
    pub k: usize,
    pub s: usize,
    pub t: usize,
}

pub struct BatchingSumcheckWitnessOutput<F: Field, MT: Config> {
    pub witnesses: Vec<Vec<F>>,
    pub acc_witnesses: AccumulatorWitnesses<F, MT>,
    pub codewords: Vec<Vec<F>>,
    pub w: Vec<F>,
}

// -----------------------------------------------------------------------
// WARP proof (sent alongside the NARG string)
// -----------------------------------------------------------------------

pub struct WARPProof<F: Field, MT: Config> {
    pub rt_0: MT::InnerDigest,
    pub mus: Vec<F>,
    pub nu_0: F,
    pub nus: Vec<F>,
    pub auth_0: Vec<Path<MT>>,
    pub auth: Vec<Vec<Path<MT>>>,
    pub shift_queries_answers: Vec<Vec<F>>,
}

// -----------------------------------------------------------------------
// WARP output: new accumulator instance + witness + proof
// -----------------------------------------------------------------------

pub struct WARPOutput<F: Field, MT: Config> {
    pub acc_instance: AccumulatorInstances<F, MT>,
    pub acc_witness: AccumulatorWitnesses<F, MT>,
    pub proof: WARPProof<F, MT>,
}
