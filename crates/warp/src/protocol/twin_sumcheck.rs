use ark_ff::{Field, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use ia_core::{ProverChannel, VerifierChannel};
use rayon::prelude::*;

use crate::relations::r1cs::R1CSConstraints;
use crate::utils::poly::{pairwise_reduce, tablewise_reduce};

/// Evaluation tables for the twin constraint sumcheck.
pub struct Evals<F> {
    pub u: Vec<Vec<F>>,
    pub z: Vec<Vec<F>>,
    pub a: Vec<Vec<F>>,
    pub b: Vec<Vec<F>>,
    pub tau: Vec<F>,
}

pub type EvalTuple<F> = (Vec<F>, Vec<F>, Vec<F>, Vec<F>);

impl<F: Clone> Evals<F> {
    pub fn new(
        u: Vec<Vec<F>>,
        z: Vec<Vec<F>>,
        a: Vec<Vec<F>>,
        b: Vec<Vec<F>>,
        tau: Vec<F>,
    ) -> Self {
        Self { u, z, a, b, tau }
    }

    pub fn get_last_evals(&mut self) -> Option<EvalTuple<F>> {
        let z = self.z.pop()?;
        let beta_tau = self.b.pop()?;
        let u = self.u.pop()?;
        let alpha = self.a.pop()?;
        Some((u, z, alpha, beta_tau))
    }
}

fn protogalaxy_trick<F: Field + Send + Sync>(
    c: impl Iterator<Item = (F, F)>,
    mut q: Vec<DensePolynomial<F>>,
) -> DensePolynomial<F> {
    for (a, b) in c {
        q = q
            .par_chunks(2)
            .map(|p| {
                &p[0]
                    + DensePolynomial::from_coefficients_vec(vec![a, b]).naive_mul(&(&p[1] - &p[0]))
            })
            .collect();
    }
    assert_eq!(q.len(), 1);
    q.pop().unwrap()
}

/// Twin constraint pseudo-batching sumcheck prover.
///
/// For each of `n_rounds` rounds:
/// 1. Compute polynomial h from evaluation tables + R1CS constraints
/// 2. Send h coefficients via channel
/// 3. Read challenge from channel
/// 4. Fold evaluation tables with challenge
pub fn prove<F, P>(
    ch: &mut P,
    evals: &mut Evals<F>,
    r1cs: &R1CSConstraints<F>,
    omega: F,
    n_rounds: usize,
    n_coeffs: usize,
) -> Vec<F>
where
    F: Field + Send + Sync,
    P: ProverChannel,
    F: spongefish::Encoding + spongefish::Decoding,
{
    let mut challenges = Vec::with_capacity(n_rounds);

    for _ in 0..n_rounds {
        let Evals { u, z, a, b, tau } = evals;

        let f_iter = u.chunks(2).zip(a.chunks(2)).map(|(u, a)| {
            protogalaxy_trick(
                a[0].iter().zip(&a[1]).map(|(&l, &r)| (l, r - l)),
                u[0].par_iter()
                    .zip(&u[1])
                    .map(|(&l, &r)| DensePolynomial::from_coefficients_vec(vec![l, r - l]))
                    .collect::<Vec<_>>(),
            )
        });

        let p_iter = b.chunks(2).zip(z.chunks(2)).map(|(b, z)| {
            protogalaxy_trick(
                b[0].iter().zip(&b[1]).map(|(&l, &r)| (l, r - l)),
                r1cs.par_iter()
                    .map(|(a_lc, b_lc, c_lc)| {
                        let a0: F = a_lc.iter().map(|(t, i)| z[0][*i] * t).sum();
                        let a1: F = a_lc.iter().map(|(t, i)| z[1][*i] * t).sum::<F>() - a0;
                        let b0: F = b_lc.iter().map(|(t, i)| z[0][*i] * t).sum();
                        let b1: F = b_lc.iter().map(|(t, i)| z[1][*i] * t).sum::<F>() - b0;
                        let c0: F = c_lc.iter().map(|(t, i)| z[0][*i] * t).sum();
                        let c1: F = c_lc.iter().map(|(t, i)| z[1][*i] * t).sum::<F>() - c0;
                        vec![a0 * b0 - c0, a0 * b1 + a1 * b0 - c1, a1 * b1]
                    })
                    .map(DensePolynomial::from_coefficients_vec)
                    .collect::<Vec<_>>(),
            )
        });

        let t_iter = tau
            .chunks(2)
            .map(|t| DensePolynomial::from_coefficients_vec(vec![t[0], t[1] - t[0]]));

        let h = f_iter
            .zip(p_iter)
            .zip(t_iter)
            .map(|((f, p), t)| (f + p * omega).naive_mul(&t))
            .fold(DensePolynomial::zero(), |acc, r| acc + r);

        let mut padded_coeffs = vec![F::zero(); n_coeffs];
        for (i, c) in h.coeffs.iter().enumerate().take(n_coeffs) {
            padded_coeffs[i] = *c;
        }
        for coeff in &padded_coeffs {
            ch.send_prover_message(coeff);
        }

        let c: F = ch.read_verifier_message();

        tablewise_reduce(u, c);
        tablewise_reduce(z, c);
        tablewise_reduce(a, c);
        tablewise_reduce(b, c);
        pairwise_reduce(tau, c);

        challenges.push(c);
    }

    challenges
}

/// Twin constraint pseudo-batching sumcheck verifier.
///
/// For each of `n_rounds` rounds:
/// 1. Read polynomial h coefficients from channel
/// 2. Check h(0) + h(1) == target
/// 3. Derive challenge from channel
/// 4. Update target = h(challenge)
///
/// Returns (challenges, coefficients_per_round) for the decision phase.
pub fn verify<F, V>(
    ch: &mut V,
    n_coeffs: usize,
    n_rounds: usize,
) -> ia_core::VerificationResult<(Vec<F>, Vec<Vec<F>>)>
where
    F: Field,
    V: VerifierChannel,
    F: spongefish::Encoding + spongefish::Decoding + ia_core::Deserialize,
{
    let mut challenges = Vec::with_capacity(n_rounds);
    let mut all_coeffs = Vec::with_capacity(n_rounds);

    for _ in 0..n_rounds {
        let mut h_coeffs = Vec::with_capacity(n_coeffs);
        for _ in 0..n_coeffs {
            let coeff: F = ch.read_prover_message()?;
            h_coeffs.push(coeff);
        }

        all_coeffs.push(h_coeffs.clone());

        let c: F = ch.send_verifier_message();
        challenges.push(c);
    }

    Ok((challenges, all_coeffs))
}
