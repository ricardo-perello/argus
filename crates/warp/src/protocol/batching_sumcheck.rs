use ark_ff::Field;
use ia_core::{ProverChannel, VerifierChannel};

use crate::utils::FastMap;

/// Inner product sumcheck prover (CBBZ23 optimization).
///
/// Given vectors f and g, proves that sum_{x in {0,1}^n} f(x) * g(x) = sigma.
///
/// For each of `n_rounds` rounds:
/// 1. Compute sum_00, sum_11, sum_0110 from current f and g
/// 2. Send these 3 scalars via channel
/// 3. Read challenge from channel
/// 4. Fold f and g with the challenge
pub fn prove<F, P>(
    ch: &mut P,
    f: &mut Vec<F>,
    g_ood_evals: &[Vec<F>],
    g_id_non_0: &FastMap<F>,
    n_rounds: usize,
) -> Vec<F>
where
    F: Field,
    P: ProverChannel,
    F: spongefish::Encoding + spongefish::Decoding,
{
    let mut challenges = Vec::with_capacity(n_rounds);
    let n = f.len();
    debug_assert!(n.is_power_of_two());

    let mut g = build_batched_g(g_ood_evals, g_id_non_0, n);

    for _ in 0..n_rounds {
        let half = f.len() / 2;

        let mut sum_00 = F::zero();
        let mut sum_11 = F::zero();
        let mut sum_0110 = F::zero();

        for i in 0..half {
            let f0 = f[2 * i];
            let f1 = f[2 * i + 1];
            let g0 = g[2 * i];
            let g1 = g[2 * i + 1];
            sum_00 += f0 * g0;
            sum_11 += f1 * g1;
            sum_0110 += f0 * g1 + f1 * g0;
        }

        ch.send_prover_message(&sum_00);
        ch.send_prover_message(&sum_11);
        ch.send_prover_message(&sum_0110);

        let c: F = ch.read_verifier_message();

        let mut new_f = Vec::with_capacity(half);
        let mut new_g = Vec::with_capacity(half);
        for i in 0..half {
            new_f.push(f[2 * i] + c * (f[2 * i + 1] - f[2 * i]));
            new_g.push(g[2 * i] + c * (g[2 * i + 1] - g[2 * i]));
        }
        *f = new_f;
        g = new_g;

        challenges.push(c);
    }

    challenges
}

/// Inner product sumcheck verifier.
///
/// For each of `n_rounds` rounds:
/// 1. Read 3 scalars (sum_00, sum_11, sum_0110) from channel
/// 2. Derive challenge from channel
///
/// Returns (challenges, sums_per_round) for the decision phase.
pub fn verify<F, V>(
    ch: &mut V,
    n_rounds: usize,
) -> ia_core::VerificationResult<(Vec<F>, Vec<[F; 3]>)>
where
    F: Field,
    V: VerifierChannel,
    F: spongefish::Encoding + spongefish::Decoding + ia_core::Deserialize,
{
    let mut challenges = Vec::with_capacity(n_rounds);
    let mut all_sums = Vec::with_capacity(n_rounds);

    for _ in 0..n_rounds {
        let sum_00: F = ch.read_prover_message()?;
        let sum_11: F = ch.read_prover_message()?;
        let sum_0110: F = ch.read_prover_message()?;

        all_sums.push([sum_00, sum_11, sum_0110]);

        let c: F = ch.send_verifier_message();
        challenges.push(c);
    }

    Ok((challenges, all_sums))
}

/// Build the batched constraint polynomial g from OOD evaluations and
/// identity-based non-zero evaluations (CBBZ23 optimization).
fn build_batched_g<F: Field>(
    ood_evals: &[Vec<F>],
    id_non_0: &FastMap<F>,
    n: usize,
) -> Vec<F> {
    let mut g = vec![F::zero(); n];

    for evals_vec in ood_evals {
        for (j, val) in evals_vec.iter().enumerate() {
            if j < n {
                g[j] += *val;
            }
        }
    }

    for (&idx, &val) in id_non_0 {
        if idx < n {
            g[idx] += val;
        }
    }

    g
}
