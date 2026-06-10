//! Bulletproofs inner-product toolkit shared by the `bulletproof_*` examples.
//!
//! This module holds only the infrastructure the three forms reuse — the
//! statement/witness types, vector arithmetic, and the recursive-halving IPA
//! loop. The protocol objects themselves live in the example binaries:
//!
//! - `bulletproof_ipa`            — the IPA as a monolithic `InteractiveArgument`
//! - `bulletproof_ipa_reduction`  — the IPA as a self-composed `InteractiveReduction`
//! - `bulletproof_range`          — the range proof, reducing to the IPA core

use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use ark_std::UniformRand;
use rand::rngs::OsRng;

use ia_core::{
    Decoding, Deserialize, Encoding, ProverChannel, VerificationError, VerificationResult,
    VerifierChannel,
};

// ---------------------------------------------------------------------------
// Statement / witness
// ---------------------------------------------------------------------------

/// Public IPA statement: `P = <a,g> + <b,h> + <a,b>*u`.
#[derive(Clone)]
pub struct IpaInstance<G: CurveGroup> {
    pub g: Vec<G>,
    pub h: Vec<G>,
    pub u: G,
    pub p: G,
}

/// Private IPA witness.
#[derive(Clone)]
pub struct IpaWitness<F> {
    pub a: Vec<F>,
    pub b: Vec<F>,
}

/// Instance binding for DSFS domain separation.
impl<G> Encoding for IpaInstance<G>
where
    G: CurveGroup + Encoding,
{
    fn encode(&self) -> impl AsRef<[u8]> {
        let mut buf = Vec::new();
        for point in self.g.iter().chain(&self.h) {
            buf.extend_from_slice(point.encode().as_ref());
        }
        buf.extend_from_slice(self.u.encode().as_ref());
        buf.extend_from_slice(self.p.encode().as_ref());
        buf
    }
}

// ---------------------------------------------------------------------------
// Vector arithmetic
// ---------------------------------------------------------------------------

pub fn inner_product<F: Field>(a: &[F], b: &[F]) -> F {
    a.iter().zip(b).map(|(x, y)| *x * *y).sum()
}

/// `<scalars, points> = sum_i scalars_i * points_i`.
pub fn msm<G: CurveGroup>(scalars: &[G::ScalarField], points: &[G]) -> G {
    scalars
        .iter()
        .zip(points)
        .map(|(s, point)| *point * *s)
        .sum()
}

pub fn hadamard<F: Field>(a: &[F], b: &[F]) -> Vec<F> {
    a.iter().zip(b).map(|(x, y)| *x * *y).collect()
}

/// `(1, base, base^2, ..., base^{n-1})`.
pub fn powers<F: Field>(base: F, n: usize) -> Vec<F> {
    let mut out = Vec::with_capacity(n);
    let mut cur = F::ONE;
    for _ in 0..n {
        out.push(cur);
        cur *= base;
    }
    out
}

// ---------------------------------------------------------------------------
// IPA core: the recursive-halving loop, reused by every form.
// ---------------------------------------------------------------------------

/// Prover side of the IPA loop. Folds `(a,b)` against `(g,h)` until length 1,
/// then sends the two surviving scalars. (The prover never needs `P`.)
#[allow(non_snake_case)]
pub fn ipa_prove_core<G, P>(
    ch: &mut P,
    mut g: Vec<G>,
    mut h: Vec<G>,
    u: G,
    mut a: Vec<G::ScalarField>,
    mut b: Vec<G::ScalarField>,
) where
    G: CurveGroup + Encoding + Deserialize,
    G::ScalarField: PrimeField + Encoding + Decoding + Deserialize,
    P: ProverChannel<Unit = u8>,
{
    assert!(a.len().is_power_of_two());
    while a.len() > 1 {
        let half = a.len() / 2;
        let (a_lo, a_hi) = a.split_at(half);
        let (b_lo, b_hi) = b.split_at(half);
        let (g_lo, g_hi) = g.split_at(half);
        let (h_lo, h_hi) = h.split_at(half);

        let c_L = inner_product(a_lo, b_hi);
        let c_R = inner_product(a_hi, b_lo);
        let L = msm(a_lo, g_hi) + msm(b_hi, h_lo) + u * c_L;
        let R = msm(a_hi, g_lo) + msm(b_lo, h_hi) + u * c_R;

        ch.send_prover_message(&L);
        ch.send_prover_message(&R);
        let x: G::ScalarField = ch.read_verifier_message();
        let x_inv = x.inverse().expect("challenge must be non-zero");

        let a_next: Vec<_> = (0..half).map(|i| a_lo[i] * x + a_hi[i] * x_inv).collect();
        let b_next: Vec<_> = (0..half).map(|i| b_lo[i] * x_inv + b_hi[i] * x).collect();
        let g_next: Vec<_> = (0..half).map(|i| g_lo[i] * x_inv + g_hi[i] * x).collect();
        let h_next: Vec<_> = (0..half).map(|i| h_lo[i] * x + h_hi[i] * x_inv).collect();
        a = a_next;
        b = b_next;
        g = g_next;
        h = h_next;
    }
    ch.send_prover_message(&a[0]);
    ch.send_prover_message(&b[0]);
}

/// Verifier side of the IPA loop. Folds `(g,h)` and `P` with the round
/// challenges, then checks the size-1 statement against the revealed scalars.
#[allow(non_snake_case)]
pub fn ipa_verify_core<G, V>(
    ch: &mut V,
    mut g: Vec<G>,
    mut h: Vec<G>,
    u: G,
    mut P: G,
) -> VerificationResult<()>
where
    G: CurveGroup + Encoding + Deserialize,
    G::ScalarField: PrimeField + Encoding + Decoding + Deserialize,
    V: VerifierChannel<Unit = u8>,
{
    let mut n = g.len();
    while n > 1 {
        let half = n / 2;
        let L: G = ch.read_prover_message()?;
        let R: G = ch.read_prover_message()?;
        let x: G::ScalarField = ch.send_verifier_message();
        let x_inv = x.inverse().ok_or(VerificationError)?;

        P = L * x.square() + P + R * x_inv.square();

        let (g_lo, g_hi) = g.split_at(half);
        let (h_lo, h_hi) = h.split_at(half);
        let g_next: Vec<_> = (0..half).map(|i| g_lo[i] * x_inv + g_hi[i] * x).collect();
        let h_next: Vec<_> = (0..half).map(|i| h_lo[i] * x + h_hi[i] * x_inv).collect();
        g = g_next;
        h = h_next;
        n = half;
    }

    let a: G::ScalarField = ch.read_prover_message()?;
    let b: G::ScalarField = ch.read_prover_message()?;
    if P == g[0] * a + h[0] * b + u * (a * b) {
        Ok(())
    } else {
        Err(VerificationError)
    }
}

/// Per-round IPA soundness: one folding round is a Laurent identity of degree 2
/// in the challenge (`x^2 ... x^-2`), so clearing denominators gives a degree-4
/// polynomial and a cheating prover survives with probability `<= 4/|F|`. This
/// is a coarse bound; the precise knowledge-soundness analysis (BCCGP16 /
/// Bulletproofs §3, forking lemma over `2 log n + 1` transcripts) is left as a
/// documented conservative limitation until that analysis is implemented.
pub fn ipa_round_error<F: PrimeField>() -> f64 {
    4.0 * 2_f64.powi(-(F::MODULUS_BIT_SIZE as i32))
}

// ---------------------------------------------------------------------------
// Statement generation
// ---------------------------------------------------------------------------

/// Build a random valid `(instance, witness)` for a length-`n` (power of two)
/// inner-product statement. Generators are sampled uniformly — i.e. with no
/// known discrete-log relations exposed to the protocol. A production system
/// would derive them via nothing-up-my-sleeve hash-to-curve.
pub fn random_statement<G>(
    n: usize,
    rng: &mut OsRng,
) -> (IpaInstance<G>, IpaWitness<G::ScalarField>)
where
    G: CurveGroup,
{
    let a: Vec<G::ScalarField> = (0..n).map(|_| G::ScalarField::rand(rng)).collect();
    let b: Vec<G::ScalarField> = (0..n).map(|_| G::ScalarField::rand(rng)).collect();
    let g: Vec<G> = (0..n).map(|_| G::rand(rng)).collect();
    let h: Vec<G> = (0..n).map(|_| G::rand(rng)).collect();
    let u = G::rand(rng);
    let c = inner_product(&a, &b);
    let p = msm(&a, &g) + msm(&b, &h) + u * c;
    (IpaInstance { g, h, u, p }, IpaWitness { a, b })
}
