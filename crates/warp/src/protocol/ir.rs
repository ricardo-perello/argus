use std::marker::PhantomData;

use ark_codes::traits::LinearCode;
use ark_crypto_primitives::merkle_tree::{Config, MerkleTree};
use ark_ff::{Field, PrimeField};
use ark_poly::{DenseMultilinearExtension, Polynomial};
use ark_std::log2;

use ia_core::{
    InteractiveArgument, InteractiveReduction, Prove, ProverChannel, ReduceProve, ReduceVerify,
    ReducedArgument, SecurityErrorBound, SecurityProfile, Verify, VerificationResult,
};

use crate::protocol::warp::{DeciderInstance, DeciderWitness, WARPInstance, WARPWitness};
use crate::relations::r1cs::R1CSConstraints;
use crate::relations::BundledPESAT;
use crate::utils::poly::{eq_poly, Hypercube};

// -----------------------------------------------------------------------
// WARPReduction: the full IOR as a single InteractiveReduction
// -----------------------------------------------------------------------

pub struct WARPReduction<F, P, C, MT>(PhantomData<(F, P, C, MT)>);

impl<F, P, C, MT> InteractiveReduction for WARPReduction<F, P, C, MT>
where
    F: Field,
    P: BundledPESAT<F>,
    C: LinearCode<F> + Clone,
    MT: Config,
{
    type SourceInstance = WARPInstance<F, P, C, MT>;
    type SourceWitness = WARPWitness<F, MT>;
    type TargetInstance = DeciderInstance<F, P, C, MT>;
    type TargetWitness = DeciderWitness<F, MT>;

    fn protocol_id() -> [u8; 64] {
        spongefish::protocol_id(core::format_args!("argus::warp::reduction"))
    }

    fn security() -> SecurityProfile {
        // TODO : Conservative placeholder bound until a full, parameterized WARP analysis
        // is encoded in the type-level IA metadata.
        SecurityProfile {
            soundness_error: SecurityErrorBound::new(|_t| 1.0),
            knowledge_soundness_error: SecurityErrorBound::new(|_t| 1.0),
            hvzk_error: SecurityErrorBound::new(|_t| 1.0),
            num_rounds: 0,
            verifier_challenge_lengths: Vec::new(),
        }
    }
}

impl<F, P, C, MT, Ch> ReduceProve<Ch> for WARPReduction<F, P, C, MT>
where
    F: Field + PrimeField + Send + Sync + spongefish::Encoding + spongefish::Decoding,
    P: Clone + BundledPESAT<F, Constraints = R1CSConstraints<F>, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone,
    MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
    Ch: ProverChannel,
{
    fn prove(
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
}

impl<F, P, C, MT, Ch> ReduceVerify<Ch> for WARPReduction<F, P, C, MT>
where
    F: Field + PrimeField + Send + Sync + spongefish::Encoding + spongefish::Decoding + ia_core::Deserialize,
    P: Clone + BundledPESAT<F, Constraints = R1CSConstraints<F>, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone,
    MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
    Ch: ia_core::VerifierChannel,
{
    fn verify(
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

// -----------------------------------------------------------------------
// WARPDeciderIA: the decider as an InteractiveArgument
// -----------------------------------------------------------------------

pub struct WARPDeciderIA<F, P, C, MT>(PhantomData<(F, P, C, MT)>);

impl<F, P, C, MT> InteractiveArgument for WARPDeciderIA<F, P, C, MT>
where
    F: Field,
    P: BundledPESAT<F>,
    C: LinearCode<F> + Clone,
    MT: Config,
{
    type Instance = DeciderInstance<F, P, C, MT>;
    type Witness = DeciderWitness<F, MT>;

    fn protocol_id() -> [u8; 64] {
        spongefish::protocol_id(core::format_args!("argus::warp::decider"))
    }

    fn security() -> SecurityProfile {
        SecurityProfile {
            soundness_error: SecurityErrorBound::zero(),
            knowledge_soundness_error: SecurityErrorBound::zero(),
            hvzk_error: SecurityErrorBound::zero(),
            num_rounds: 0,
            verifier_challenge_lengths: Vec::new(),
        }
    }
}

impl<F, P, C, MT, Ch> Prove<Ch> for WARPDeciderIA<F, P, C, MT>
where
    F: Field + PrimeField + Send + Sync + spongefish::Encoding + spongefish::Decoding,
    P: Clone + BundledPESAT<F, Constraints = R1CSConstraints<F>, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone,
    MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
    Ch: ProverChannel,
{
    fn prove(ch: &mut Ch, _instance: &DeciderInstance<F, P, C, MT>, witness: &DeciderWitness<F, MT>) {
        let (_trees, codewords, w_parts) = witness;
        for val in &codewords[0] {
            ch.send_prover_message(val);
        }
        for val in &w_parts[0] {
            ch.send_prover_message(val);
        }
    }
}

impl<F, P, C, MT, Ch> Verify<Ch> for WARPDeciderIA<F, P, C, MT>
where
    F: Field + PrimeField + Send + Sync + spongefish::Encoding + spongefish::Decoding + ia_core::Deserialize,
    P: Clone + BundledPESAT<F, Constraints = R1CSConstraints<F>, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone,
    MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
    Ch: ia_core::VerifierChannel,
{
    fn verify(
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

// -----------------------------------------------------------------------
// FullWARP = ReducedArgument<WARPReduction, WARPDeciderIA>  (IR . IA -> IA)
// -----------------------------------------------------------------------

pub type FullWARP<F, P, C, MT> =
    ReducedArgument<WARPReduction<F, P, C, MT>, WARPDeciderIA<F, P, C, MT>>;
