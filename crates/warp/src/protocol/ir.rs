use std::marker::PhantomData;

use ark_codes::traits::LinearCode;
use ark_crypto_primitives::merkle_tree::{Config, MerkleTree};
use ark_ff::{Field, PrimeField};
use ark_poly::{DenseMultilinearExtension, Polynomial};
use ark_std::log2;

use ia_core::{
    InteractiveArgument, InteractiveReduction, ProtocolSecurity, ProverChannel,
    ReducedArgument, SecurityErrorBound, SecurityProfile, VerificationResult, VerifierChannel,
};

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
    _phantom: PhantomData<(F, P, C, MT)>,
}

impl<F, P, C, MT> WARPReduction<F, P, C, MT> {
    pub fn new(log_l: usize, log_n: usize, log_m: usize) -> Self {
        Self { log_l, log_n, log_m, _phantom: PhantomData }
    }
}

impl<F, P, C, MT> Default for WARPReduction<F, P, C, MT> {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

impl<F, P, C, MT> InteractiveReduction for WARPReduction<F, P, C, MT>
where
    F: Field + PrimeField + Send + Sync + spongefish::Encoding + spongefish::Decoding + ia_core::Deserialize,
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
        // Per-round RBR error via Schwartz–Zippel: deg/|F| where deg is the
        // polynomial degree sent by the prover in that round.
        //
        // Twin sumcheck (log_l rounds, protocol/twin_sumcheck.rs):
        //   n_coeffs = 2 + max(log_n + 1, log_m + 2)
        //   degree   = n_coeffs - 1 = 1 + max(log_n, log_m + 1)
        //
        // Batching sumcheck (log_n rounds, protocol/batching_sumcheck.rs):
        //   sends sum_00, sum_11, sum_0110 → degree 2
        //
        // SecurityErrorBound stores bare fn pointers (no closures). To represent
        // deg/|F|, we store `deg` copies of the 1/|F| function and rely on the
        // additive evaluation: sum of deg identical terms = deg * (1/|F|).
        //
        // WARP is public-coin with no ZK, so hvzk_error = 0.
        fn one_over_field_size<F: PrimeField>(_t: u64) -> f64 {
            2_f64.powi(-(F::MODULUS_BIT_SIZE as i32))
        }

        // Twin sumcheck degree = 1 + max(log_n, log_m + 1).
        // When log_m = 0 (unknown / not set), this is at least 1.
        let twin_deg = 1 + self.log_n.max(self.log_m + 1);
        // Batching sumcheck degree = 2 (three scalars per round → degree-2 polynomial).
        let batch_deg: usize = 2;

        // Build a SecurityErrorBound representing deg/|F| by composing `deg`
        // single-term bounds of 1/|F|. This uses only the public API.
        let make_deg_bound = |deg: usize| -> SecurityErrorBound {
            let single = SecurityErrorBound::new(one_over_field_size::<F>);
            (1..deg).fold(single.clone(), |acc, _| acc.compose(&single))
        };

        let twin_rbr: Vec<SecurityErrorBound> = (0..self.log_l)
            .map(|_| make_deg_bound(twin_deg))
            .collect();
        let batch_rbr: Vec<SecurityErrorBound> = (0..self.log_n)
            .map(|_| make_deg_bound(batch_deg))
            .collect();

        let mut rbr = twin_rbr;
        rbr.extend(batch_rbr);

        SecurityProfile {
            plain_soundness_error: SecurityErrorBound::zero(),
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
    F: Field + PrimeField + Send + Sync + spongefish::Encoding + spongefish::Decoding + ia_core::Deserialize,
    P: Clone + BundledPESAT<F, Constraints = R1CSConstraints<F>, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone,
    MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
{
    type Instance = DeciderInstance<F, P, C, MT>;
    type Witness = DeciderWitness<F, MT>;

    fn protocol_id(&self) -> impl AsRef<[u8]> {
        ia_core::pad_protocol_id(b"argus::warp::decider")
    }

    fn prove<Ch: ProverChannel>(&self, ch: &mut Ch, _instance: &DeciderInstance<F, P, C, MT>, witness: &DeciderWitness<F, MT>) {
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
