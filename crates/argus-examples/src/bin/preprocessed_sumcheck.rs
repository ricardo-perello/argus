//! Preprocessed multilinear sumcheck — first example of an
//! `PreprocessingInteractiveReduction`.
//!
//! All previous preprocessed examples (preprocessed_schnorr, dleq,
//! preprocessed_lookup) implement [`ia_core::PreprocessingInteractiveArgument`]: the
//! verifier outputs accept/reject. This one implements
//! [`ia_core::PreprocessingInteractiveReduction`]: the verifier outputs a *new target
//! instance* that a downstream decider then checks.
//!
//! The protocol is the standard multilinear sumcheck of Lund-Fortnow-
//! Karloff-Nisan, specialized to a 2-variable multilinear polynomial
//! `p(X, Y) = c_00 + c_10·X + c_01·Y + c_11·X·Y` for readability. It
//! reduces the claim
//!
//! ```text
//! T  =  Σ_{x ∈ {0,1}^2}  p(x)
//! ```
//!
//! to a single-point evaluation claim
//!
//! ```text
//! v  =  p(r_1, r_2)         for verifier-chosen (r_1, r_2)
//! ```
//!
//! The reduction is the building block of essentially every modern SNARK
//! (Spartan, HyperPlonk, Lasso, …); the preprocessed polynomial maps onto
//! the indexed surface as:
//!
//!   Index          = [F; 4]               (the four multilinear coeffs)
//!   ProverKey      = SumcheckProverKey    { coeffs }
//!   VerifierKey    = SumcheckVerifierKey  { commit: blake3 of coeffs }
//!   SourceInstance = F                    (claimed sum T)
//!   SourceWitness  = ()
//!   TargetInstance = ((F, F), F)          ((r_1, r_2), v)
//!   TargetWitness  = ()
//!
//! Asymmetric on purpose: the verifier never needs the raw coefficients
//! during the reduction (it only checks the per-round polynomials sent
//! by the prover), so the verifier key compresses to a 32-byte commitment.
//! A separate downstream decider — given access to pk via some opening
//! protocol — closes the soundness loop by checking v == p(r_1, r_2).
//! The example's `main` runs that decider step locally.
//!
//! Per-round verifier check (the soundness heart of sumcheck): the prover
//! sends a linear polynomial q_i. The verifier asserts
//! `q_i(0) + q_i(1) == previous_claim` before squeezing the next
//! challenge. If at any point the prover lied about an intermediate
//! claim, this two-point check catches it with overwhelming probability.
//!
//! Run:  cargo run -p argus-examples --bin preprocessed_sumcheck

use ark_bls12_381::Fr;
use ark_ff::AdditiveGroup;
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use rand::rngs::OsRng;
use spongefish_dsfs as dsfs;

use ia_core::{
    CommittedIndexBytes, NonInteractiveReduction, Preprocessed, ProverChannel, VerificationError,
    VerificationResult, VerifierChannel, VerifierKeyCommitment,
};

// ---------------------------------------------------------------------------
// Multilinear polynomial in 2 variables, hard-coded layout
// ---------------------------------------------------------------------------

const C00: usize = 0;
const C10: usize = 1;
const C01: usize = 2;
const C11: usize = 3;

/// Evaluate p(x, y) = c_00 + c_10·x + c_01·y + c_11·x·y.
fn eval(coeffs: &[Fr; 4], x: Fr, y: Fr) -> Fr {
    coeffs[C00] + coeffs[C10] * x + coeffs[C01] * y + coeffs[C11] * x * y
}

/// Sum of p(x, y) over (x, y) in {0, 1}^2.
/// Expands to 4·c_00 + 2·c_10 + 2·c_01 + c_11.
fn sum_over_hypercube(coeffs: &[Fr; 4]) -> Fr {
    coeffs[C00].double().double() + coeffs[C10].double() + coeffs[C01].double() + coeffs[C11]
}

/// Round-1 polynomial q_1(X) = p(X, 0) + p(X, 1), as (constant, linear).
/// q_1(X) = (2·c_00 + c_01) + (2·c_10 + c_11) · X
fn round1(coeffs: &[Fr; 4]) -> (Fr, Fr) {
    (
        coeffs[C00].double() + coeffs[C01],
        coeffs[C10].double() + coeffs[C11],
    )
}

/// Round-2 polynomial q_2(Y) = p(r_1, Y), as (constant, linear).
/// q_2(Y) = (c_00 + c_10·r_1) + (c_01 + c_11·r_1) · Y
fn round2(coeffs: &[Fr; 4], r1: Fr) -> (Fr, Fr) {
    (
        coeffs[C00] + coeffs[C10] * r1,
        coeffs[C01] + coeffs[C11] * r1,
    )
}

/// Evaluate a degree-1 polynomial (const, lin) at `x`.
fn line(poly: (Fr, Fr), x: Fr) -> Fr {
    poly.0 + poly.1 * x
}

/// Two-point sum p(0) + p(1) for a degree-1 polynomial: 2·c + l.
fn two_point_sum(poly: (Fr, Fr)) -> Fr {
    poly.0.double() + poly.1
}

// ---------------------------------------------------------------------------
// Asymmetric prover key / verifier key
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct SumcheckProverKey {
    coeffs: [Fr; 4],
}

#[derive(Clone, Debug)]
struct SumcheckVerifierKey {
    /// Blake3 commitment to the canonical-serialized coefficients. Lets
    /// the prepared transcript bind a proof to *this* polynomial without
    /// the verifier ever needing to hold the coefficients themselves.
    commit: [u8; 32],
}

fn hash_coeffs(coeffs: &[Fr; 4]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for c in coeffs {
        let mut buf = Vec::new();
        c.serialize_compressed(&mut buf).expect("Fr serialization");
        hasher.update(&buf);
    }
    *hasher.finalize().as_bytes()
}

impl VerifierKeyCommitment for SumcheckVerifierKey {
    fn committed_index(&self) -> CommittedIndexBytes {
        let mut out = Vec::with_capacity(b"preprocessed-sumcheck:vk:v1".len() + 32);
        out.extend_from_slice(b"preprocessed-sumcheck:vk:v1");
        out.extend_from_slice(&self.commit);
        CommittedIndexBytes::new(out)
    }
}

// ---------------------------------------------------------------------------
// The body — implements the indexed *reduction* trait
// ---------------------------------------------------------------------------

#[derive(Default)]
struct PreprocessedSumcheck;

ia_core::impl_preprocessing_reduction! {
    impl PreprocessingInteractiveReduction for PreprocessedSumcheck {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            ia_core::pad_protocol_id(b"preprocessed-sumcheck-n2")
        }

        /// Claimed sum T.
        type SourceInstance = Fr;
        /// ((r_1, r_2), v)
        type TargetInstance = ((Fr, Fr), Fr);
        type SourceWitness = ();
        type TargetWitness = ();
        type Index = [Fr; 4];
        type ProverKey = SumcheckProverKey;
        type VerifierKey = SumcheckVerifierKey;

        fn index(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
            let pk = SumcheckProverKey { coeffs: *ix };
            let vk = SumcheckVerifierKey {
                commit: hash_coeffs(ix),
            };
            (pk, vk)
        }

        fn prove<P: ProverChannel>(
            &self,
            ch: &mut P,
            pk: &SumcheckProverKey,
            _source: &Fr,
            _w: &(),
        ) -> (((Fr, Fr), Fr), ()) {
            // Round 1: send q_1(X) = p(X, 0) + p(X, 1) as (const, lin).
            let q1 = round1(&pk.coeffs);
            ch.send_prover_message(&q1.0);
            ch.send_prover_message(&q1.1);
            let r1: Fr = ch.read_verifier_message();

            // Round 2: send q_2(Y) = p(r_1, Y) as (const, lin).
            let q2 = round2(&pk.coeffs, r1);
            ch.send_prover_message(&q2.0);
            ch.send_prover_message(&q2.1);
            let r2: Fr = ch.read_verifier_message();

            // Target: v = p(r_1, r_2) = q_2(r_2).
            let v = line(q2, r2);
            (((r1, r2), v), ())
        }

        fn verify<V: VerifierChannel>(
            &self,
            ch: &mut V,
            _vk: &SumcheckVerifierKey,
            source: &Fr,
        ) -> VerificationResult<((Fr, Fr), Fr)> {
            let t = *source;

            // Round 1 check: q_1(0) + q_1(1) = T.
            let q1c: Fr = ch.read_prover_message()?;
            let q1l: Fr = ch.read_prover_message()?;
            if two_point_sum((q1c, q1l)) != t {
                return Err(VerificationError);
            }
            let r1: Fr = ch.send_verifier_message();
            let next_claim = line((q1c, q1l), r1);

            // Round 2 check: q_2(0) + q_2(1) = q_1(r_1).
            let q2c: Fr = ch.read_prover_message()?;
            let q2l: Fr = ch.read_prover_message()?;
            if two_point_sum((q2c, q2l)) != next_claim {
                return Err(VerificationError);
            }
            let r2: Fr = ch.send_verifier_message();

            // Target instance: the still-unverified claim "v = p(r_1, r_2)".
            // A downstream decider closes the loop by checking it against the
            // actual polynomial (which it can do given pk, or via some opening
            // protocol on vk.commit).
            let v = line((q2c, q2l), r2);
            Ok(((r1, r2), v))
        }
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    println!("=== Preprocessed multilinear sumcheck (n=2) ===\n");
    let session = spongefish::session!("preprocessed sumcheck example");

    // Sample a random multilinear polynomial in 2 variables.
    let mut rng = OsRng;
    let coeffs: [Fr; 4] = [
        Fr::rand(&mut rng),
        Fr::rand(&mut rng),
        Fr::rand(&mut rng),
        Fr::rand(&mut rng),
    ];
    let t = sum_over_hypercube(&coeffs);
    println!("Picked p(X, Y) with 4 random coefficients.");
    println!("Claimed sum  T = Σ_{{x∈{{0,1}}^2}} p(x) = {t}\n");

    // Preprocessing: preprocessing_non_interactive_reduction wraps an indexed
    // reduction; .prepare(&ix) calls body.index(&ix) once and stashes
    // (pk, vk, committed_index) inside the returned PreparedDsfsReduction.
    let prepared = dsfs::preprocessing_non_interactive_reduction(
        PreprocessedSumcheck,
        dsfs::Keccak::default(),
    )
    .prepare(&coeffs);

    // Inspect asymmetry via the `Preprocessed` capability.
    fn report<P: Preprocessed>(label: &str, p: &P)
    where
        P::VerifierKey: core::fmt::Debug,
    {
        println!("{label}:");
        println!("  Verifier key: {:?}", p.verifier_key());
        println!(
            "  Committed index: 0x{}\n",
            hex::encode(p.committed_index().as_bytes())
        );
    }
    report("Preprocessed wrapper (via `Preprocessed`)", &prepared);

    // Run the reduction. Source instance is just T; witness is ().
    let (proof, target_prover, ()) = prepared.prove(&session, &t, &());
    let target_verifier = prepared
        .verify(&session, &t, &proof)
        .expect("sumcheck reduction verifies");
    assert_eq!(target_prover, target_verifier);

    let ((r1, r2), v_claim) = target_verifier;
    println!("Reduced (T) -> ((r_1, r_2), v):");
    println!("  r_1 = {r1}");
    println!("  r_2 = {r2}");
    println!("  v   = {v_claim}\n");

    // Decider step: independently evaluate p at (r_1, r_2) and check.
    // In real protocols this is a separate IA executed by the prover, but
    // here we just compute it locally to show the reduction was honest.
    let v_true = eval(&coeffs, r1, r2);
    assert_eq!(
        v_claim, v_true,
        "decider must accept the reduction's target"
    );
    println!("Decider: p(r_1, r_2) = {v_true} matches v ✓");
    println!("Proof size: {} bytes\n", proof.as_bytes().len());
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ia_core::PreparedReduction;

    fn sample_coeffs() -> [Fr; 4] {
        let mut rng = OsRng;
        [
            Fr::rand(&mut rng),
            Fr::rand(&mut rng),
            Fr::rand(&mut rng),
            Fr::rand(&mut rng),
        ]
    }

    /// Honest prover with correct T: reduction round-trips and the
    /// target evaluation matches the actual polynomial value.
    #[test]
    fn sumcheck_roundtrip_and_decider_accepts() {
        let session = spongefish::session!("preprocessed sumcheck test");
        let coeffs = sample_coeffs();
        let t = sum_over_hypercube(&coeffs);
        let prepared = dsfs::preprocessing_non_interactive_reduction(
            PreprocessedSumcheck,
            dsfs::Keccak::default(),
        )
        .prepare(&coeffs);

        let (proof, _target_p, ()) = prepared.prove(&session, &t, &());
        let ((r1, r2), v) = prepared.verify(&session, &t, &proof).expect("verify");

        assert_eq!(eval(&coeffs, r1, r2), v, "decider check");
    }

    #[test]
    fn sumcheck_roundtrip_prepare_then_dsfs() {
        let session = spongefish::session!("preprocessed sumcheck prepared-reduction test");
        let coeffs = sample_coeffs();
        let t = sum_over_hypercube(&coeffs);

        let prepared_sumcheck = PreparedReduction::prepare(PreprocessedSumcheck, &coeffs);
        let indexed_source = prepared_sumcheck.indexed_source(t);
        let prepared_nir_sumcheck = dsfs::plain_non_interactive_reduction::<_, [u8; 64], _>(
            prepared_sumcheck,
            dsfs::Keccak::default(),
        );

        let (proof, target_p, ()) = prepared_nir_sumcheck.prove(&session, &indexed_source, &());
        let target_v = prepared_nir_sumcheck
            .verify(&session, &indexed_source, &proof)
            .expect("prepare then DSFS reduction verifies");
        assert_eq!(target_p, target_v);

        let ((r1, r2), v) = target_v;
        assert_eq!(eval(&coeffs, r1, r2), v, "decider check");
    }

    #[test]
    fn sumcheck_prepare_then_dsfs_matches_dsfs_then_prepare_exactly() {
        let session = spongefish::session!("preprocessed sumcheck route-equivalence test");
        let coeffs = sample_coeffs();
        let t = sum_over_hypercube(&coeffs);
        let direct = dsfs::preprocessing_non_interactive_reduction(
            PreprocessedSumcheck,
            dsfs::Keccak::default(),
        )
        .prepare(&coeffs);

        let prepared_sumcheck = PreparedReduction::prepare(PreprocessedSumcheck, &coeffs);
        assert_eq!(
            direct.committed_index(),
            prepared_sumcheck.committed_index()
        );

        let indexed_source = prepared_sumcheck.indexed_source(t);
        let prepared_first = dsfs::plain_non_interactive_reduction::<_, [u8; 64], _>(
            prepared_sumcheck,
            dsfs::Keccak::default(),
        );

        let (direct_proof, direct_target, ()) = direct.prove(&session, &t, &());
        let (prepared_first_proof, prepared_first_target, ()) =
            prepared_first.prove(&session, &indexed_source, &());
        assert_eq!(
            direct_proof.as_bytes(),
            prepared_first_proof.as_bytes(),
            "deterministic reduction should produce identical proof bytes through both prepared routes"
        );
        assert_eq!(direct_target, prepared_first_target);

        let direct_verified_target = direct
            .verify(&session, &t, &prepared_first_proof)
            .expect("direct prepared DSFS verifies the prepare-then-DSFS proof");
        let prepared_verified_target = prepared_first
            .verify(&session, &indexed_source, &direct_proof)
            .expect("prepare-then-DSFS verifies the direct prepared proof");
        assert_eq!(direct_verified_target, direct_target);
        assert_eq!(prepared_verified_target, prepared_first_target);
    }

    /// If the prover claims a wrong T, the round-1 two-point check fails
    /// at verification time. This is the soundness payoff of sumcheck:
    /// any lie about an intermediate claim is caught locally.
    #[test]
    fn sumcheck_rejects_wrong_t() {
        let session = spongefish::session!("preprocessed sumcheck test");
        let coeffs = sample_coeffs();
        let real_t = sum_over_hypercube(&coeffs);
        let fake_t = real_t + Fr::from(1u64);

        let prepared = dsfs::preprocessing_non_interactive_reduction(
            PreprocessedSumcheck,
            dsfs::Keccak::default(),
        )
        .prepare(&coeffs);

        // Prover honestly runs on (its true) `coeffs`. But the caller
        // passes the wrong T as the source instance. The verifier reads
        // the round-1 polynomial, computes q_1(0)+q_1(1) (which equals
        // real_t), and finds it != fake_t. Reject.
        let (proof, _, ()) = prepared.prove(&session, &fake_t, &());
        assert!(prepared.verify(&session, &fake_t, &proof).is_err());
    }

    /// Two prepared wrappers over different polynomials have different
    /// committed indices; a proof produced under one cannot be verified
    /// under the other (transcript divergence catches it).
    #[test]
    fn sumcheck_proof_does_not_cross_polynomials() {
        let session = spongefish::session!("preprocessed sumcheck test");
        let coeffs_a = sample_coeffs();
        let mut coeffs_b = coeffs_a;
        coeffs_b[C11] += Fr::from(1u64); // perturb one coefficient

        let prepared_a = dsfs::preprocessing_non_interactive_reduction(
            PreprocessedSumcheck,
            dsfs::Keccak::default(),
        )
        .prepare(&coeffs_a);
        let prepared_b = dsfs::preprocessing_non_interactive_reduction(
            PreprocessedSumcheck,
            dsfs::Keccak::default(),
        )
        .prepare(&coeffs_b);
        assert_ne!(prepared_a.committed_index(), prepared_b.committed_index());

        let t_a = sum_over_hypercube(&coeffs_a);
        let (proof, _, ()) = prepared_a.prove(&session, &t_a, &());
        assert!(prepared_b.verify(&session, &t_a, &proof).is_err());
    }

    /// `Preprocessed` capability extracts vk from any prepared wrapper,
    /// reduction-flavored or argument-flavored.
    #[test]
    fn preprocessed_capability_reaches_sumcheck_vk_generically() {
        fn vk_commit_bytes<P: Preprocessed>(p: &P) -> Vec<u8> {
            p.committed_index().as_bytes().to_vec()
        }
        let coeffs = sample_coeffs();
        let prepared = dsfs::preprocessing_non_interactive_reduction::<_, [u8; 64], _>(
            PreprocessedSumcheck,
            dsfs::Keccak::default(),
        )
        .prepare(&coeffs);
        let bytes = vk_commit_bytes(&prepared);
        assert!(bytes.starts_with(b"preprocessed-sumcheck:vk:v1"));
    }
}
