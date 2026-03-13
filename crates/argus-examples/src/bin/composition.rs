//! Sequential composition example.
//!
//! Demonstrates `ChainedReduction` (IR . IR -> IR) and `ReducedArgument`
//! (IR . IA -> IA) by composing three protocols into a pipeline:
//!
//!   FoldPairs     (IR): n claims -> n/2 claims   (pairwise random fold)
//!   Accumulate    (IR): n claims -> single pair   (random linear combination)
//!   EqualityCheck (IA): checks pair equality      (trivial decider)
//!
//! Full pipeline (8 values):
//!   FoldPairs . FoldPairs . Accumulate . EqualityCheck
//!   8 -> 4 -> 2 -> (acc_claim, acc_value) -> accept/reject

use ark_curve25519::Fr;
use ark_ff::{AdditiveGroup, Field};
use ark_std::UniformRand;
use rand::rngs::OsRng;

use ia_core::{
    ChainedReduction, InteractiveArgument, InteractiveReduction, Prove, ReduceProve, ReduceVerify,
    ReducedArgument, Verify, VerificationError, VerificationResult,
};

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

/// Public claims (source/target instance for reductions that preserve shape).
#[derive(Clone, spongefish::Encoding)]
struct Claims(Vec<Fr>);

/// Prover-side values (source/target witness for fold-like reductions).
struct Values(Vec<Fr>);

/// Accumulated pair: the final IR target instance.
#[derive(Debug)]
struct AccPair {
    claim: Fr,
    value: Fr,
}

// ---------------------------------------------------------------------------
// IR: FoldPairs -- folds n pairs into n/2 via a random linear combination
//
//   Source relation: claims[i] == values[i] for all i
//   Target relation: folded_claims[j] == folded_values[j] for all j
//
//   Soundness: Schwartz-Zippel on the degree-1 polynomial
//     (claims[2k] - values[2k]) + r * (claims[2k+1] - values[2k+1])
// ---------------------------------------------------------------------------

struct FoldPairs;

impl InteractiveReduction for FoldPairs {
    type SourceInstance = Claims;
    type TargetInstance = Claims;
    type SourceWitness = Values;
    type TargetWitness = Values;

    fn protocol_id() -> [u8; 64] {
        spongefish::protocol_id(core::format_args!("fold pairs"))
    }
}

impl<P: ia_core::ProverChannel> ReduceProve<P> for FoldPairs {
    fn prove(ch: &mut P, instance: &Claims, witness: &Values) -> (Claims, Values) {
        let n = instance.0.len();
        assert!(n % 2 == 0 && n >= 2);

        for w_i in &witness.0 {
            ch.send_prover_message(w_i);
        }
        let r: Fr = ch.read_verifier_message();

        let mut folded_claims = Vec::with_capacity(n / 2);
        let mut folded_values = Vec::with_capacity(n / 2);
        for i in (0..n).step_by(2) {
            folded_claims.push(instance.0[i] + r * instance.0[i + 1]);
            folded_values.push(witness.0[i] + r * witness.0[i + 1]);
        }

        (Claims(folded_claims), Values(folded_values))
    }
}

impl<V: ia_core::VerifierChannel> ReduceVerify<V> for FoldPairs {
    fn verify(ch: &mut V, instance: &Claims) -> VerificationResult<Claims> {
        let n = instance.0.len();

        // Read prover-committed values (absorbed into transcript before the
        // challenge is derived, but not used in the target-instance computation).
        for _ in 0..n {
            let _v: Fr = ch.read_prover_message()?;
        }
        let r: Fr = ch.send_verifier_message();

        let mut folded = Vec::with_capacity(n / 2);
        for i in (0..n).step_by(2) {
            folded.push(instance.0[i] + r * instance.0[i + 1]);
        }

        Ok(Claims(folded))
    }
}

// ---------------------------------------------------------------------------
// IR: Accumulate -- reduces n claims+values to a single (acc_claim, acc_value)
// ---------------------------------------------------------------------------

struct Accumulate;

impl InteractiveReduction for Accumulate {
    type SourceInstance = Claims;
    type TargetInstance = AccPair;
    type SourceWitness = Values;
    type TargetWitness = ();

    fn protocol_id() -> [u8; 64] {
        spongefish::protocol_id(core::format_args!("accumulate"))
    }
}

impl<P: ia_core::ProverChannel> ReduceProve<P> for Accumulate {
    fn prove(ch: &mut P, instance: &Claims, witness: &Values) -> (AccPair, ()) {
        let n = instance.0.len();

        for w_i in &witness.0 {
            ch.send_prover_message(w_i);
        }
        let alpha: Fr = ch.read_verifier_message();

        let mut acc_claim = Fr::ZERO;
        let mut acc_value = Fr::ZERO;
        let mut power = Fr::ONE;
        for i in 0..n {
            acc_claim += power * instance.0[i];
            acc_value += power * witness.0[i];
            power *= alpha;
        }

        (AccPair { claim: acc_claim, value: acc_value }, ())
    }
}

impl<V: ia_core::VerifierChannel> ReduceVerify<V> for Accumulate {
    fn verify(ch: &mut V, instance: &Claims) -> VerificationResult<AccPair> {
        let n = instance.0.len();

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
            acc_claim += power * instance.0[i];
            acc_value += power * values[i];
            power *= alpha;
        }

        Ok(AccPair { claim: acc_claim, value: acc_value })
    }
}

// ---------------------------------------------------------------------------
// IA: EqualityCheck -- trivial decider that checks acc_claim == acc_value
// ---------------------------------------------------------------------------

struct EqualityCheck;

impl InteractiveArgument for EqualityCheck {
    type Instance = AccPair;
    type Witness = ();

    fn protocol_id() -> [u8; 64] {
        spongefish::protocol_id(core::format_args!("equality check"))
    }
}

impl<P: ia_core::ProverChannel> Prove<P> for EqualityCheck {
    fn prove(_ch: &mut P, _instance: &AccPair, _witness: &()) {}
}

impl<V: ia_core::VerifierChannel> Verify<V> for EqualityCheck {
    fn verify(_ch: &mut V, instance: &AccPair) -> VerificationResult<()> {
        if instance.claim == instance.value {
            Ok(())
        } else {
            Err(VerificationError)
        }
    }
}

// ---------------------------------------------------------------------------
// Composed types
// ---------------------------------------------------------------------------

/// IR . IR -> IR: fold twice (8 -> 4 -> 2)
type TwoFolds = ChainedReduction<FoldPairs, FoldPairs>;

/// (IR . IR) . IR -> IR: fold twice then accumulate (8 -> 4 -> 2 -> pair)
type FoldAndAccumulate = ChainedReduction<TwoFolds, Accumulate>;

/// IR . IA -> IA: full pipeline ending in accept/reject
type FullProtocol = ReducedArgument<FoldAndAccumulate, EqualityCheck>;

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let n: usize = 8;

    let values: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut OsRng)).collect();
    let claims = values.clone();

    let instance = Claims(claims);
    let witness = Values(values);

    let session = spongefish::session!("argus example: composition");

    // -- 1. ChainedReduction: FoldPairs . FoldPairs (IR . IR -> IR) ----------

    println!("=== ChainedReduction: FoldPairs . FoldPairs (IR . IR -> IR) ===");
    println!("    8 values -> 4 -> 2\n");

    let proof = dsfs::prove_reduction::<TwoFolds>(session, &instance, &witness);
    println!("  proof ({} bytes): {}", proof.len(), hex::encode(&proof));

    let target = dsfs::verify_reduction::<TwoFolds>(session, &instance, &proof)
        .expect("two-fold reduction failed");
    println!("  target claims (2 elements): {:?}", target.0);
    println!("  [OK] two-fold reduction verified\n");

    // -- 2. Full pipeline: (Fold . Fold . Accumulate) . EqualityCheck --------

    println!("=== ReducedArgument: (Fold . Fold . Accumulate) . EqualityCheck ===");
    println!("    8 values -> 4 -> 2 -> AccPair -> accept/reject\n");

    let proof = dsfs::prove::<FullProtocol>(session, &instance, &witness);
    println!("  proof ({} bytes): {}", proof.len(), hex::encode(&proof));

    dsfs::verify::<FullProtocol>(session, &instance, &proof)
        .expect("full protocol verification failed");
    println!("  [OK] full composed protocol verified");
}
