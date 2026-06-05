//! Bulletproofs range proof (S&P 2018, §4.2).
//!
//! Proves a Pedersen commitment opens to an in-range value:
//!
//! ```text
//!   V = v*g_base + gamma*h_base ,   prove v in [0, 2^N)
//! ```
//!
//! The range statement is reduced to an inner product and discharged with the
//! shared IPA core (`ipa_prove_core` / `ipa_verify_core`). Unlike the bare IPA
//! this **is** zero-knowledge: the blinding (`alpha, rho, s_L, s_R, tau_1,
//! tau_2`) makes it perfect SHVZK.
//!
//! Transcript: `send A,S -> squeeze y,z -> send T1,T2 -> squeeze x ->
//! send tau_x,mu,t_hat -> squeeze w -> IPA on (g, h'=y^-i h, u*w, P')`.
//!
//! Run with:  cargo run -p argus-examples --bin bulletproof_range

use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{AdditiveGroup, Field, PrimeField};
use ark_std::{log2, UniformRand};
use rand::rngs::OsRng;
use spongefish_dsfs as dsfs;

use argus_examples::bulletproofs::{
    hadamard, inner_product, ipa_prove_core, ipa_round_error, ipa_verify_core, msm, powers,
};
use ia_core::prelude::*;
use ia_core::{
    ArgumentSecurity, Decoding, Deserialize, Encoding, ProverChannel,
    SecurityErrorBound, SecurityProfile, VerificationError, VerificationResult, VerifierChannel,
};

// ---------------------------------------------------------------------------
// Public parameters (CRS), statement, witness
// ---------------------------------------------------------------------------

/// `u` is the IPA base `u_0` that gets challenge-scaled (`u_0 * w`) before the
/// inner-product argument.
#[derive(Clone)]
pub struct RangeParams<G: CurveGroup> {
    pub g_base: G,
    pub h_base: G,
    pub g_vec: Vec<G>,
    pub h_vec: Vec<G>,
    pub u: G,
}

impl<G: CurveGroup> RangeParams<G> {
    fn n_bits(&self) -> usize {
        self.g_vec.len()
    }
}

struct RangeProof<G: CurveGroup> {
    params: RangeParams<G>,
}

impl<G: CurveGroup> RangeProof<G> {
    fn new(params: RangeParams<G>) -> Self {
        Self { params }
    }
}

#[derive(Clone)]
struct RangeInstance<G: CurveGroup> {
    commitment: G,
}

impl<G> Encoding for RangeInstance<G>
where
    G: CurveGroup + Encoding,
{
    fn encode(&self) -> impl AsRef<[u8]> {
        self.commitment.encode().as_ref().to_vec()
    }
}

#[derive(Clone)]
struct RangeWitness<F> {
    v: u64,
    gamma: F,
}

// ---------------------------------------------------------------------------
// Protocol
// ---------------------------------------------------------------------------

ia_core::impl_interactive_argument! {
    impl<G> InteractiveArgument for RangeProof<G>
    where
        G: CurveGroup + PrimeGroup + Encoding + Deserialize,
        G::ScalarField: PrimeField + Encoding + Decoding + Deserialize,
    {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            ia_core::pad_protocol_id(b"bulletproofs-range")
        }

        type Instance = RangeInstance<G>;
        type Witness = RangeWitness<G::ScalarField>;

        #[allow(non_snake_case)]
        fn prove<P: ProverChannel<Unit = u8>>(
            &self,
            ch: &mut P,
            _instance: &RangeInstance<G>,
            witness: &RangeWitness<G::ScalarField>,
        ) {
            type F<G> = <G as PrimeGroup>::ScalarField;
            let params = &self.params;
            let n = params.n_bits();
            let (g_base, h_base) = (params.g_base, params.h_base);

            // Bit decomposition: a_L in {0,1}^n with <a_L, 2^n> = v, a_R = a_L - 1.
            let a_L: Vec<F<G>> = (0..n)
                .map(|i| if (witness.v >> i) & 1 == 1 { F::<G>::ONE } else { F::<G>::ZERO })
                .collect();
            let a_R: Vec<F<G>> = a_L.iter().map(|bit| *bit - F::<G>::ONE).collect();

            // Blinding.
            let alpha = F::<G>::rand(&mut OsRng);
            let rho = F::<G>::rand(&mut OsRng);
            let s_L: Vec<F<G>> = (0..n).map(|_| F::<G>::rand(&mut OsRng)).collect();
            let s_R: Vec<F<G>> = (0..n).map(|_| F::<G>::rand(&mut OsRng)).collect();

            let A = h_base * alpha + msm(&a_L, &params.g_vec) + msm(&a_R, &params.h_vec);
            let S = h_base * rho + msm(&s_L, &params.g_vec) + msm(&s_R, &params.h_vec);
            ch.send_prover_message(&A);
            ch.send_prover_message(&S);

            let y: F<G> = ch.read_verifier_message();
            let z: F<G> = ch.read_verifier_message();

            let y_pows = powers(y, n);
            let two_pows = powers(F::<G>::from(2u64), n);
            let z2 = z.square();

            // l(X) = (a_L - z) + s_L X ;  r(X) = y^n o (a_R + z + s_R X) + z^2 2^n
            let l0: Vec<F<G>> = a_L.iter().map(|x| *x - z).collect();
            let l1 = s_L.clone();
            let a_R_plus_z: Vec<F<G>> = a_R.iter().map(|x| *x + z).collect();
            let r0: Vec<F<G>> = (0..n)
                .map(|i| y_pows[i] * a_R_plus_z[i] + z2 * two_pows[i])
                .collect();
            let r1 = hadamard(&y_pows, &s_R);

            // t(X) = <l,r> = t0 + t1 X + t2 X^2.
            let t1 = inner_product(&l0, &r1) + inner_product(&l1, &r0);
            let t2 = inner_product(&l1, &r1);
            let tau1 = F::<G>::rand(&mut OsRng);
            let tau2 = F::<G>::rand(&mut OsRng);
            let T1 = g_base * t1 + h_base * tau1;
            let T2 = g_base * t2 + h_base * tau2;
            ch.send_prover_message(&T1);
            ch.send_prover_message(&T2);

            let x: F<G> = ch.read_verifier_message();

            let l: Vec<F<G>> = (0..n).map(|i| l0[i] + l1[i] * x).collect();
            let r: Vec<F<G>> = (0..n).map(|i| r0[i] + r1[i] * x).collect();
            let t_hat = inner_product(&l, &r);
            let tau_x = tau2 * x.square() + tau1 * x + z2 * witness.gamma;
            let mu = alpha + rho * x;
            ch.send_prover_message(&tau_x);
            ch.send_prover_message(&mu);
            ch.send_prover_message(&t_hat);

            // Bind the inner-product base with a fresh challenge so the prover
            // cannot smuggle a u-component through A/S.
            let w: F<G> = ch.read_verifier_message();
            let u_ipa = params.u * w;

            // h'_i = y^{-i} h_i, so <r, h'> matches the basis the verifier rebuilds.
            let y_inv = y.inverse().expect("challenge must be non-zero");
            let y_inv_pows = powers(y_inv, n);
            let h_prime: Vec<G> = (0..n).map(|i| params.h_vec[i] * y_inv_pows[i]).collect();

            ipa_prove_core(ch, params.g_vec.clone(), h_prime, u_ipa, l, r);
        }

        #[allow(non_snake_case)]
        fn verify<V: VerifierChannel<Unit = u8>>(
            &self,
            ch: &mut V,
            instance: &RangeInstance<G>,
        ) -> VerificationResult<()> {
            type F<G> = <G as PrimeGroup>::ScalarField;
            let params = &self.params;
            let n = params.n_bits();
            let (g_base, h_base) = (params.g_base, params.h_base);
            let V_comm = instance.commitment;

            let A: G = ch.read_prover_message()?;
            let S: G = ch.read_prover_message()?;
            let y: F<G> = ch.send_verifier_message();
            let z: F<G> = ch.send_verifier_message();
            let T1: G = ch.read_prover_message()?;
            let T2: G = ch.read_prover_message()?;
            let x: F<G> = ch.send_verifier_message();
            let tau_x: F<G> = ch.read_prover_message()?;
            let mu: F<G> = ch.read_prover_message()?;
            let t_hat: F<G> = ch.read_prover_message()?;
            let w: F<G> = ch.send_verifier_message();

            let y_pows = powers(y, n);
            let two_pows = powers(F::<G>::from(2u64), n);
            let z2 = z.square();
            let z3 = z2 * z;

            // delta(y,z) = (z - z^2)<1, y^n> - z^3 <1, 2^n>.
            let sum_y: F<G> = y_pows.iter().copied().sum();
            let sum_two: F<G> = two_pows.iter().copied().sum();
            let delta = (z - z2) * sum_y - z3 * sum_two;

            // Check 1: t_hat commitment ties t_hat to V.
            let lhs = g_base * t_hat + h_base * tau_x;
            let rhs = V_comm * z2 + g_base * delta + T1 * x + T2 * x.square();
            if lhs != rhs {
                return Err(VerificationError);
            }

            // Rebuild the inner-product commitment P' and discharge it via the IPA.
            let u_ipa = params.u * w;
            let y_inv = y.inverse().ok_or(VerificationError)?;
            let y_inv_pows = powers(y_inv, n);
            let h_prime: Vec<G> = (0..n).map(|i| params.h_vec[i] * y_inv_pows[i]).collect();

            // P_pre = A + xS - mu h_base + <-z, g> + <z y^n + z^2 2^n, h'>.
            let neg_z = vec![-z; n];
            let h_coeffs: Vec<F<G>> = (0..n).map(|i| z * y_pows[i] + z2 * two_pows[i]).collect();
            let p_pre = A + S * x - h_base * mu
                + msm(&neg_z, &params.g_vec)
                + msm(&h_coeffs, &h_prime);
            let p_prime = p_pre + u_ipa * t_hat;

            ipa_verify_core(ch, params.g_vec.clone(), h_prime, u_ipa, p_prime)
        }
    }
}

impl<G> ArgumentSecurity for RangeProof<G>
where
    G: CurveGroup + PrimeGroup + Encoding + Deserialize,
    G::ScalarField: PrimeField + Encoding + Decoding + Deserialize,
{
    type InstanceParams = usize; // n_bits
    type InstanceBound = usize;

    fn instance_security_params(&self, _instance: &Self::Instance) -> usize {
        self.params.n_bits()
    }

    fn instance_bound_for_instance_params(&self, params: &usize) -> usize {
        *params
    }

    fn profile_for_instance_params(&self, params: &usize) -> SecurityProfile {
        range_profile::<G::ScalarField>(*params)
    }

    fn profile_for_instance_bound(&self, bound: &usize) -> SecurityProfile {
        range_profile::<G::ScalarField>(*bound)
    }
}

/// Coarse range-proof profile. Challenges in order: `y, z, x, w`, then the
/// `log2(n)` IPA rounds. Perfect SHVZK (`hvzk_error = 0`). The non-IPA rounds
/// (degree-2 `t(X)` plus the bit constraints) carry more than the IPA's `4/|F|`;
/// the precise per-round decomposition is a TODO — this is a placeholder bound.
fn range_profile<F: PrimeField>(n_bits: usize) -> SecurityProfile {
    let log_n = log2(n_bits) as usize;
    let per_round = ipa_round_error::<F>(); // coarse; see doc comment
    let rounds = 4 + log_n;
    let rbr: Vec<SecurityErrorBound> = (0..rounds)
        .map(|_| SecurityErrorBound::new(move |_t| per_round))
        .collect();

    SecurityProfile {
        plain_soundness_error: SecurityErrorBound::new(move |_t| (rounds as f64) * per_round),
        rbr_soundness_errors: rbr.clone(),
        rbr_knowledge_soundness_errors: rbr,
        hvzk_error: SecurityErrorBound::zero(), // perfect SHVZK
        verifier_challenge_lengths: vec![1; rounds],
    }
}

// ---------------------------------------------------------------------------
// Statement generation
// ---------------------------------------------------------------------------

fn random_range_params<G: CurveGroup>(n_bits: usize, rng: &mut OsRng) -> RangeParams<G> {
    RangeParams {
        g_base: G::rand(rng),
        h_base: G::rand(rng),
        g_vec: (0..n_bits).map(|_| G::rand(rng)).collect(),
        h_vec: (0..n_bits).map(|_| G::rand(rng)).collect(),
        u: G::rand(rng),
    }
}

fn commit_value<G: CurveGroup>(params: &RangeParams<G>, v: u64, gamma: G::ScalarField) -> G {
    params.g_base * G::ScalarField::from(v) + params.h_base * gamma
}

// ---------------------------------------------------------------------------
// Demo
// ---------------------------------------------------------------------------

type Demo = ark_curve25519::EdwardsProjective;

fn main() {
    let n_bits = 8;
    let v = 100u64;
    println!("=== Bulletproofs range proof, v = {v} in [0, 2^{n_bits}) ===\n");
    let params = random_range_params::<Demo>(n_bits, &mut OsRng);
    let gamma = <Demo as PrimeGroup>::ScalarField::rand(&mut OsRng);
    let commitment = commit_value(&params, v, gamma);
    let instance = RangeInstance { commitment };
    let witness = RangeWitness { v, gamma };

    let session = spongefish::session!("bulletproofs range example");
    let nia = dsfs::plain_non_interactive_argument(RangeProof::new(params), dsfs::Keccak::default());
    let narg = nia.prove(&session, &instance, &witness);
    println!("Proof: {} bytes", narg.as_bytes().len());
    nia.verify(&session, &instance, &narg).expect("range verification failed");
    println!("Verification succeeded");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    type G = ark_curve25519::EdwardsProjective;
    type F = ark_curve25519::Fr;

    fn range_roundtrip(v: u64) {
        let n_bits = 8;
        let params = random_range_params::<G>(n_bits, &mut OsRng);
        let gamma = F::rand(&mut OsRng);
        let commitment = commit_value(&params, v, gamma);
        let instance = RangeInstance { commitment };
        let witness = RangeWitness { v, gamma };

        let session = spongefish::session!("bulletproofs range test");
        let nia =
            dsfs::plain_non_interactive_argument(RangeProof::new(params), dsfs::Keccak::default());
        let narg = nia.prove(&session, &instance, &witness);
        nia.verify(&session, &instance, &narg)
            .unwrap_or_else(|_| panic!("range verification failed for v = {v}"));
    }

    #[test]
    fn range_proof_boundaries_and_midpoint() {
        range_roundtrip(0); // min
        range_roundtrip(255); // max for 8 bits
        range_roundtrip(100); // mid
    }

    #[test]
    fn range_proof_rejects_wrong_commitment() {
        // Build a valid proof for v=100, then verify against a commitment to v=101.
        let n_bits = 8;
        let params = random_range_params::<G>(n_bits, &mut OsRng);
        let gamma = F::rand(&mut OsRng);
        let honest = RangeInstance { commitment: commit_value(&params, 100, gamma) };
        let tampered = RangeInstance { commitment: commit_value(&params, 101, gamma) };
        let witness = RangeWitness { v: 100, gamma };

        let session = spongefish::session!("bulletproofs range test");
        let nia =
            dsfs::plain_non_interactive_argument(RangeProof::new(params), dsfs::Keccak::default());
        let narg = nia.prove(&session, &honest, &witness);
        assert!(nia.verify(&session, &tampered, &narg).is_err());
    }
}
