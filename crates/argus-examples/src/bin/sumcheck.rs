use ark_curve25519::Fr;
use ark_ff::{One, Zero};
use ark_std::UniformRand;
use rand::rngs::OsRng;
use spongefish::Encoding;
use spongefish_dsfs as dsfs;

use ia_core::prelude::*;
use ia_core::{ProverChannel, VerificationError, VerificationResult, VerifierChannel};

struct SumcheckProver;
struct SumcheckVerifier;

#[derive(Clone, Encoding)]
struct Instance {
    /// Number of variables \(n\) for a function \(f : \{0,1\}^n \to \mathbb{F}\).
    n: u32,
    /// A concrete description of \(f\) for the warmup: its evaluations on \(\{0,1\}^n\).
    ///
    /// Length must be exactly \(2^n\).
    evals: Vec<Fr>,
    /// The claimed value \(S = \sum_{x \in \{0,1\}^n} f(x)\).
    claimed_sum: Fr,
}

impl SumcheckProver {
    fn expected_table_len(n: u32) -> Option<usize> {
        1usize.checked_shl(n)
    }

    /// Warmup sumcheck prover for a multilinear function given by its full table on `{0,1}^n`.
    ///
    /// Convention: `x_1` is the least-significant bit of the index into `evals`, so round 1
    /// pairs entries `(0,1), (2,3), ...`.
    fn prove_sumcheck<P: ProverChannel<Unit = u8>>(ch: &mut P, instance: &Instance) {
        let n = instance.n as usize;
        let expected = Self::expected_table_len(instance.n).expect("n is too large for usize");
        assert_eq!(
            instance.evals.len(),
            expected,
            "instance.evals must have length 2^n"
        );

        let mut table = instance.evals.clone();
        let mut claim = instance.claimed_sum;

        for _round in 0..n {
            debug_assert!(table.len().is_power_of_two());
            debug_assert!(table.len() >= 2);

            // g_i(0) and g_i(1) are the sums over the "even" and "odd" halves of each pair.
            let mut s0 = Fr::zero();
            let mut s1 = Fr::zero();
            for pair in table.chunks_exact(2) {
                s0 += pair[0];
                s1 += pair[1];
            }

            // (Optional sanity check) g_i(0) + g_i(1) must match the running claim.
            debug_assert_eq!(s0 + s1, claim);

            // Prover message α_i: the linear polynomial g_i represented by its values at 0 and 1.
            ch.send_prover_message(&s0);
            ch.send_prover_message(&s1);

            // Verifier message ρ_i: challenge r_i (public coin).
            let r_i: Fr = ch.read_verifier_message();
            let one_minus_r = Fr::one() - r_i;

            // Update running claim S_i = g_i(r_i).
            claim = one_minus_r * s0 + r_i * s1;

            // Fold the table: v' = (1-r) * v0 + r * v1 for each pair.
            let mut next = Vec::with_capacity(table.len() / 2);
            for pair in table.chunks_exact(2) {
                next.push(one_minus_r * pair[0] + r_i * pair[1]);
            }
            table = next;
        }

        debug_assert_eq!(table.len(), 1);
        debug_assert_eq!(table[0], claim);
    }
}

impl SumcheckVerifier {
    fn expected_table_len(n: u32) -> Option<usize> {
        1usize.checked_shl(n)
    }

    fn verify_sumcheck<V: VerifierChannel<Unit = u8>>(
        ch: &mut V,
        instance: &Instance,
    ) -> VerificationResult<()> {
        let Some(expected) = Self::expected_table_len(instance.n) else {
            return Err(VerificationError);
        };
        let n = instance.n as usize;
        if instance.evals.len() != expected {
            return Err(VerificationError);
        }

        let mut claim = instance.claimed_sum;
        let mut table = instance.evals.clone();

        for _round in 0..n {
            let s0: Fr = ch.read_prover_message()?;
            let s1: Fr = ch.read_prover_message()?;
            if s0 + s1 != claim {
                return Err(VerificationError);
            }

            let r_i: Fr = ch.send_verifier_message();
            let one_minus_r = Fr::one() - r_i;
            claim = one_minus_r * s0 + r_i * s1;
            // Fold the table: v' = (1-r) * v0 + r * v1 for each pair.
            let mut next = Vec::with_capacity(table.len() / 2);
            for pair in table.chunks_exact(2) {
                next.push(one_minus_r * pair[0] + r_i * pair[1]);
            }
            table = next;
        }

        if table.first().copied() == Some(claim) {
            Ok(())
        } else {
            Err(VerificationError)
        }
    }
}

ia_core::impl_interactive_argument! {
    impl {
        prover: SumcheckProver,
        verifier: SumcheckVerifier,
    }
    {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            ia_core::pad_protocol_id(b"sumcheck proof")
        }

        type Instance = Instance;
        type Witness = ();

        fn prove<P: ProverChannel<Unit = u8>>(
            &self,
            ch: &mut P,
            instance: &Instance,
            _witness: &(),
        ) {
            Self::prove_sumcheck(ch, instance);
        }

        fn verify<V: VerifierChannel<Unit = u8>>(
            &self,
            ch: &mut V,
            instance: &Instance,
        ) -> VerificationResult<()> {
            Self::verify_sumcheck(ch, instance)
        }
    }
}

fn main() {
    // Set up instance.
    let n: u32 = 4;
    let size = 1usize << (n as usize);

    let mut rng = OsRng;
    let evals = (0..size).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
    let claimed_sum = evals.iter().copied().sum();

    let instance = Instance {
        n,
        evals,
        claimed_sum,
    };

    let session = spongefish::session!("argus examples");
    let prover =
        dsfs::argument_prover(SumcheckProver, dsfs::Keccak::default());
    let verifier =
        dsfs::argument_verifier(SumcheckVerifier, dsfs::Keccak::default());
    let proof = prover.prove(&session, &instance, &());

    println!("Sumcheck proof bytes:\n{}", hex::encode(proof.as_bytes()));

    verifier
        .verify(&session, &instance, &proof)
        .expect("Invalid proof");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sumcheck_dsfs_roundtrip() {
        let n: u32 = 4;
        let size = 1usize << n as usize;
        let evals: Vec<Fr> = (0..size as u64).map(Fr::from).collect();
        let claimed_sum = evals.iter().copied().sum();

        let instance = Instance {
            n,
            evals,
            claimed_sum,
        };

        let session = spongefish::session!("argus examples");
        let prover =
            dsfs::argument_prover(SumcheckProver, dsfs::Keccak::default());
        let verifier = dsfs::argument_verifier(
            SumcheckVerifier,
            dsfs::Keccak::default(),
        );
        let proof = prover.prove(&session, &instance, &());

        verifier
            .verify(&session, &instance, &proof)
            .expect("sumcheck verification failed");
    }

    #[test]
    fn sumcheck_rejects_wrong_claimed_sum() {
        let n: u32 = 4;
        let size = 1usize << n as usize;
        let evals: Vec<Fr> = (0..size as u64).map(Fr::from).collect();
        let claimed_sum = evals.iter().copied().sum();

        let instance = Instance {
            n,
            evals,
            claimed_sum,
        };

        let session = spongefish::session!("argus examples");
        let prover =
            dsfs::argument_prover(SumcheckProver, dsfs::Keccak::default());
        let verifier = dsfs::argument_verifier(
            SumcheckVerifier,
            dsfs::Keccak::default(),
        );
        let proof = prover.prove(&session, &instance, &());

        let bad_instance = Instance {
            claimed_sum: instance.claimed_sum + Fr::one(),
            ..instance
        };

        assert!(verifier.verify(&session, &bad_instance, &proof).is_err());
    }
}
