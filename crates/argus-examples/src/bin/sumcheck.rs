use ark_curve25519::Fr;
use ark_ff::{One, Zero};
use ark_std::UniformRand;
use rand::rngs::OsRng;
use spongefish::{protocol_id, DomainSeparator, Encoding, ProverState};

struct Sumcheck;

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

impl Sumcheck {
    pub fn protocol_id() -> [u8; 64] {
        protocol_id(core::format_args!("sumcheck proof"))
    }

    /// Warmup sumcheck prover for a multilinear function given by its full table on `{0,1}^n`.
    ///
    /// Convention: `x_1` is the least-significant bit of the index into `evals`, so round 1
    /// pairs entries `(0,1), (2,3), ...`.
    pub fn prove<'a>(prover_state: &'a mut ProverState, instance: &Instance) -> &'a [u8] {
        let n = instance.n as usize;
        let expected = 1usize << n;
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
            prover_state.prover_messages(&[s0, s1]);

            // Verifier message ρ_i: challenge r_i (public coin). In DSFS this is squeezed.
            let r_i: Fr = prover_state.verifier_message();
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

        prover_state.narg_string()
    }

    //verify
    pub fn verify(
        mut verifier_state: spongefish::VerifierState,
        instance: &Instance,
    ) -> spongefish::VerificationResult<()> {
        let mut claim = instance.claimed_sum;
        let mut table = instance.evals.clone();
        let n = instance.n as usize;

        for _round in 0..n {
            let [s0, s1] = verifier_state.prover_messages::<Fr, 2>()?;
            assert_eq!(s0 + s1, claim);
            let r_i: Fr = verifier_state.verifier_message();
            let one_minus_r = Fr::one() - r_i;
            claim = one_minus_r * s0 + r_i * s1;
            //fold the table: v' = (1-r) * v0 + r * v1 for each pair.
            let mut next = Vec::with_capacity(table.len() / 2);
            for pair in table.chunks_exact(2) {
                next.push(one_minus_r * pair[0] + r_i * pair[1]);
            }
            table = next;
        }
        assert_eq!(table[0], claim);
        verifier_state.check_eof()?;
        Ok(())
    }

}

fn main() {
    //set up instance
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

    let domain_separator = DomainSeparator::new(Sumcheck::protocol_id())
        .session(spongefish::session!("argus examples"))
        .instance(&instance);

    let mut prover_state = domain_separator.std_prover();
    let narg_string = Sumcheck::prove(&mut prover_state, &instance);


    println!("Sumcheck proof bytes:\n{}", hex::encode(narg_string));

    let verifier_state = domain_separator.std_verifier(narg_string);
    Sumcheck::verify(verifier_state, &instance).expect("Invalid proof");
}
