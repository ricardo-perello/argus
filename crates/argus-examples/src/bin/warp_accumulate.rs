//! WARP-style accumulation via the InteractiveReduction + DSFS stack.
//!
//! Demonstrates a simple accumulation IOR (interactive oracle reduction)
//! modeled on WARP's random-linear-combination core.
//!
//! Protocol:
//!   Source instance: n claimed values c_1, ..., c_n (public)
//!   Witness: actual values w_1, ..., w_n (prover knows)
//!   Prover sends each w_i through the channel
//!   Verifier reads them, squeezes random alpha
//!   Verifier computes:
//!     acc_claim = sum(alpha^i * c_i)
//!     acc_value = sum(alpha^i * w_i)
//!   Target instance: (acc_claim, acc_value)
//!   Decider (separate): checks acc_claim == acc_value
//!
//! Soundness: if any c_i != w_i, then acc_claim != acc_value
//!   w.h.p. by Schwartz-Zippel (probability >= 1 - n/|F|).

use ark_curve25519::Fr;
use ark_ff::{AdditiveGroup, Field};
use ark_std::UniformRand;
use rand::rngs::OsRng;

use ia_core::{
    InteractiveReduction, ReduceProve, ReduceVerify, VerificationError, VerificationResult,
};

// ---------------------------------------------------------------------------
// Source instance codec (needs Encoding for DSFS domain separation)
// ---------------------------------------------------------------------------

#[derive(Clone, spongefish::Encoding)]
struct SourceInstance {
    claims: Vec<Fr>,
}

// ---------------------------------------------------------------------------
// Target instance (what the verifier computes)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct TargetInstance {
    acc_claim: Fr,
    acc_value: Fr,
}

// ---------------------------------------------------------------------------
// Protocol type
// ---------------------------------------------------------------------------

struct Accumulate;

// ---------------------------------------------------------------------------
// InteractiveReduction: metadata
// ---------------------------------------------------------------------------

impl InteractiveReduction for Accumulate {
    type SourceInstance = SourceInstance;
    type TargetInstance = TargetInstance;
    type SourceWitness = Vec<Fr>;
    type TargetWitness = ();

    fn protocol_id() -> [u8; 64] {
        spongefish::protocol_id(core::format_args!(
            "warp-style random linear combination accumulator"
        ))
    }
}

// ---------------------------------------------------------------------------
// ReduceProve: prover sends witness values, reads challenge
// ---------------------------------------------------------------------------

impl<P: ia_core::ProverChannel> ReduceProve<P> for Accumulate {
    fn prove(
        ch: &mut P,
        instance: &SourceInstance,
        witness: &Vec<Fr>,
    ) -> (TargetInstance, ()) {
        let n = instance.claims.len();

        for w_i in witness {
            ch.send_prover_message(w_i);
        }
        let alpha: Fr = ch.read_verifier_message();

        let mut acc_claim = Fr::ZERO;
        let mut acc_value = Fr::ZERO;
        let mut power = Fr::ONE;
        for i in 0..n {
            acc_claim += power * instance.claims[i];
            acc_value += power * witness[i];
            power *= alpha;
        }

        (TargetInstance { acc_claim, acc_value }, ())
    }
}

// ---------------------------------------------------------------------------
// ReduceVerify: verifier reads witness values, squeezes alpha, computes
//               accumulated (claim, value) pair
// ---------------------------------------------------------------------------

impl<V: ia_core::VerifierChannel> ReduceVerify<V> for Accumulate {
    fn verify(ch: &mut V, instance: &SourceInstance) -> VerificationResult<TargetInstance> {
        let n = instance.claims.len();

        let mut values = Vec::with_capacity(n);
        for _ in 0..n {
            let w_i: Fr = ch.read_prover_message()?;
            values.push(w_i);
        }

        let alpha: Fr = ch.send_verifier_message();

        let mut acc_claim = Fr::ZERO;
        let mut acc_value = Fr::ZERO;
        let mut power = Fr::ONE;
        for i in 0..n {
            acc_claim += power * instance.claims[i];
            acc_value += power * values[i];
            power *= alpha;
        }

        Ok(TargetInstance {
            acc_claim,
            acc_value,
        })
    }
}

// ---------------------------------------------------------------------------
// Decider: checks the accumulated pair (separate from the IOR)
// ---------------------------------------------------------------------------

fn decide(target: &TargetInstance) -> VerificationResult<()> {
    if target.acc_claim == target.acc_value {
        Ok(())
    } else {
        Err(VerificationError)
    }
}

// ---------------------------------------------------------------------------
// Main: prove, verify (get target instance), decide
// ---------------------------------------------------------------------------

fn main() {
    let n = 8;

    let values: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut OsRng)).collect();
    let claims = values.clone();

    let instance = SourceInstance { claims };
    let witness = values;

    let session = spongefish::session!("argus example: warp accumulate");

    let proof = dsfs::prove_reduction::<Accumulate>(session, &instance, &witness);
    println!(
        "Accumulation proof ({n} instances, {} bytes):\n{}",
        proof.len(),
        hex::encode(&proof)
    );

    let target = dsfs::verify_reduction::<Accumulate>(session, &instance, &proof)
        .expect("reduction failed");
    println!(
        "Reduction succeeded -> target instance:\n  acc_claim = {:?}\n  acc_value = {:?}",
        target.acc_claim, target.acc_value
    );

    decide(&target).expect("decider rejected");
    println!("Decider accepted");
}
