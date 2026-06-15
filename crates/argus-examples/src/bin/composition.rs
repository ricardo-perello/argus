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
use spongefish_dsfs as dsfs;

use ia_core::prelude::*;
use ia_core::{
    ArgumentSecurity, ChainedReduction, ProverChannel, ReducedArgument, ReductionSecurity,
    SecurityErrorBound, SecurityProfile, VerificationError, VerificationResult, VerifierChannel,
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

#[derive(Default)]
struct FoldPairsProver;
#[derive(Default)]
struct FoldPairsVerifier;

ia_core::impl_interactive_reduction_prover! {
    impl for FoldPairsProver {
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        ia_core::pad_protocol_id(b"fold pairs")
    }

    type SourceInstance = Claims;
    type TargetInstance = Claims;
    type SourceWitness = Values;
    type TargetWitness = Values;

    fn prove<P: ProverChannel<Unit = u8>>(
        &self,
        ch: &mut P,
        instance: &Claims,
        witness: &Values,
    ) -> (Claims, Values) {
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
}

ia_core::impl_interactive_reduction_verifier! {
    impl for FoldPairsVerifier {
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        ia_core::pad_protocol_id(b"fold pairs")
    }

    type SourceInstance = Claims;
    type TargetInstance = Claims;

    fn verify<V: VerifierChannel<Unit = u8>>(
        &self,
        ch: &mut V,
        instance: &Claims,
    ) -> VerificationResult<Claims> {
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
}

impl ReductionSecurity for FoldPairsVerifier {
    type SourceParams = ();
    type SourceBound = ();
    type TargetBound = ();

    fn source_security_params(&self, _instance: &Self::SourceInstance) -> Self::SourceParams {}

    fn source_bound_for_source_params(&self, _params: &Self::SourceParams) -> Self::SourceBound {}

    fn target_bound_for_source_params(&self, _params: &Self::SourceParams) -> Self::TargetBound {}

    fn target_bound_for_source_bound(&self, _bound: &Self::SourceBound) -> Self::TargetBound {}

    fn profile_for_source_params(&self, _params: &Self::SourceParams) -> SecurityProfile {
        self.profile_for_source_bound(&())
    }

    fn profile_for_source_bound(&self, _bound: &Self::SourceBound) -> SecurityProfile {
        SecurityProfile {
            plain_soundness_error: SecurityErrorBound::zero(),
            rbr_soundness_errors: vec![SecurityErrorBound::zero()],
            rbr_knowledge_soundness_errors: vec![],
            hvzk_error: SecurityErrorBound::zero(),
            verifier_challenge_lengths: vec![1],
        }
    }
}

// ---------------------------------------------------------------------------
// IR: Accumulate -- reduces n claims+values to a single (acc_claim, acc_value)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct AccumulateProver;
#[derive(Default)]
struct AccumulateVerifier;

ia_core::impl_interactive_reduction_prover! {
    impl for AccumulateProver {
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        ia_core::pad_protocol_id(b"accumulate")
    }

    type SourceInstance = Claims;
    type TargetInstance = AccPair;
    type SourceWitness = Values;
    type TargetWitness = ();

    fn prove<P: ProverChannel<Unit = u8>>(
        &self,
        ch: &mut P,
        instance: &Claims,
        witness: &Values,
    ) -> (AccPair, ()) {
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

        (
            AccPair {
                claim: acc_claim,
                value: acc_value,
            },
            (),
        )
    }

}
}

ia_core::impl_interactive_reduction_verifier! {
    impl for AccumulateVerifier {
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        ia_core::pad_protocol_id(b"accumulate")
    }

    type SourceInstance = Claims;
    type TargetInstance = AccPair;

    fn verify<V: VerifierChannel<Unit = u8>>(
        &self,
        ch: &mut V,
        instance: &Claims,
    ) -> VerificationResult<AccPair> {
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
        for (claim_i, value_i) in instance.0.iter().zip(values.iter()) {
            acc_claim += power * claim_i;
            acc_value += power * value_i;
            power *= alpha;
        }

        Ok(AccPair {
            claim: acc_claim,
            value: acc_value,
        })
    }
}
}

impl ReductionSecurity for AccumulateVerifier {
    type SourceParams = ();
    type SourceBound = ();
    type TargetBound = ();

    fn source_security_params(&self, _instance: &Self::SourceInstance) -> Self::SourceParams {}

    fn source_bound_for_source_params(&self, _params: &Self::SourceParams) -> Self::SourceBound {}

    fn target_bound_for_source_params(&self, _params: &Self::SourceParams) -> Self::TargetBound {}

    fn target_bound_for_source_bound(&self, _bound: &Self::SourceBound) -> Self::TargetBound {}

    fn profile_for_source_params(&self, _params: &Self::SourceParams) -> SecurityProfile {
        self.profile_for_source_bound(&())
    }

    fn profile_for_source_bound(&self, _bound: &Self::SourceBound) -> SecurityProfile {
        SecurityProfile {
            plain_soundness_error: SecurityErrorBound::zero(),
            rbr_soundness_errors: vec![SecurityErrorBound::zero()],
            rbr_knowledge_soundness_errors: vec![],
            hvzk_error: SecurityErrorBound::zero(),
            verifier_challenge_lengths: vec![1],
        }
    }
}

// ---------------------------------------------------------------------------
// IA: EqualityCheck -- trivial decider that checks acc_claim == acc_value
// ---------------------------------------------------------------------------

#[derive(Default)]
struct EqualityCheckProver;
#[derive(Default)]
struct EqualityCheckVerifier;

ia_core::impl_interactive_argument_prover! {
    impl for EqualityCheckProver {
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        ia_core::pad_protocol_id(b"equality check")
    }

    type Instance = AccPair;
    type Witness = ();

    fn prove<P: ProverChannel<Unit = u8>>(&self, _ch: &mut P, _instance: &AccPair, _witness: &()) {}

}
}

ia_core::impl_interactive_argument_verifier! {
    impl for EqualityCheckVerifier {
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        ia_core::pad_protocol_id(b"equality check")
    }

    type Instance = AccPair;

    fn verify<V: VerifierChannel<Unit = u8>>(
        &self,
        _ch: &mut V,
        instance: &AccPair,
    ) -> VerificationResult<()> {
        if instance.claim == instance.value {
            Ok(())
        } else {
            Err(VerificationError)
        }
    }
}
}

impl ArgumentSecurity for EqualityCheckVerifier {
    type InstanceParams = ();
    type InstanceBound = ();

    fn instance_security_params(&self, _instance: &Self::Instance) -> Self::InstanceParams {}

    fn instance_bound_for_instance_params(
        &self,
        _params: &Self::InstanceParams,
    ) -> Self::InstanceBound {
    }

    fn profile_for_instance_params(&self, _params: &Self::InstanceParams) -> SecurityProfile {
        self.profile_for_instance_bound(&())
    }

    fn profile_for_instance_bound(&self, _bound: &Self::InstanceBound) -> SecurityProfile {
        SecurityProfile {
            plain_soundness_error: SecurityErrorBound::zero(),
            rbr_soundness_errors: vec![],
            rbr_knowledge_soundness_errors: vec![],
            hvzk_error: SecurityErrorBound::zero(),
            verifier_challenge_lengths: vec![],
        }
    }
}

// ---------------------------------------------------------------------------
// Composed types
// ---------------------------------------------------------------------------

/// IR . IR -> IR: fold twice (8 -> 4 -> 2)
type TwoFoldsProver = ChainedReduction<FoldPairsProver, FoldPairsProver>;
type TwoFoldsVerifier = ChainedReduction<FoldPairsVerifier, FoldPairsVerifier>;

/// (IR . IR) . IR -> IR: fold twice then accumulate (8 -> 4 -> 2 -> pair)
type FoldAndAccumulateProver = ChainedReduction<TwoFoldsProver, AccumulateProver>;
type FoldAndAccumulateVerifier = ChainedReduction<TwoFoldsVerifier, AccumulateVerifier>;

/// IR . IA -> IA: full pipeline ending in accept/reject
type FullProtocolProver = ReducedArgument<FoldAndAccumulateProver, EqualityCheckProver>;
type FullProtocolVerifier = ReducedArgument<FoldAndAccumulateVerifier, EqualityCheckVerifier>;

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

    let prover = dsfs::reduction_prover(TwoFoldsProver::default(), dsfs::Keccak::default());
    let verifier = dsfs::reduction_verifier(TwoFoldsVerifier::default(), dsfs::Keccak::default());
    let (proof, target, _) = prover.prove(&session, &instance, &witness);
    println!(
        "  proof ({} bytes): {}",
        proof.len(),
        hex::encode(proof.as_bytes())
    );

    let verified_target = verifier
        .verify(&session, &instance, &proof)
        .expect("two-fold reduction failed");
    debug_assert_eq!(verified_target.0, target.0);
    println!("  target claims (2 elements): {:?}", verified_target.0);
    println!("  [OK] two-fold reduction verified\n");

    // -- 2. Full pipeline: (Fold . Fold . Accumulate) . EqualityCheck --------

    println!("=== ReducedArgument: (Fold . Fold . Accumulate) . EqualityCheck ===");
    println!("    8 values -> 4 -> 2 -> AccPair -> accept/reject\n");

    let prover = dsfs::argument_prover(FullProtocolProver::default(), dsfs::Keccak::default());
    let verifier =
        dsfs::argument_verifier(FullProtocolVerifier::default(), dsfs::Keccak::default());
    let proof = prover.prove(&session, &instance, &witness);
    println!(
        "  proof ({} bytes): {}",
        proof.len(),
        hex::encode(proof.as_bytes())
    );

    verifier
        .verify(&session, &instance, &proof)
        .expect("full protocol verification failed");
    println!("  [OK] full composed protocol verified");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ia_core::{
        NonInteractiveArgumentProver, NonInteractiveArgumentVerifier,
        NonInteractiveReductionProver, NonInteractiveReductionVerifier,
    };

    fn assert_narg_prover<N: NonInteractiveArgumentProver>(_: &N) {}

    fn assert_narg_verifier<N: NonInteractiveArgumentVerifier>(_: &N) {}

    fn assert_nir_prover<N: NonInteractiveReductionProver>(_: &N) {}

    fn assert_nir_verifier<N: NonInteractiveReductionVerifier>(_: &N) {}

    #[test]
    fn composition_dsfs_roundtrip() {
        let n = 8;
        let values: Vec<Fr> = (0..n as u64).map(Fr::from).collect();
        let instance = Claims(values.clone());
        let witness = Values(values);

        let session = spongefish::session!("argus example: composition");
        let prover = dsfs::argument_prover(FullProtocolProver::default(), dsfs::Keccak::default());
        let verifier =
            dsfs::argument_verifier(FullProtocolVerifier::default(), dsfs::Keccak::default());
        let proof = prover.prove(&session, &instance, &witness);
        verifier
            .verify(&session, &instance, &proof)
            .expect("verification failed");

        let reduction_prover = dsfs::reduction_prover::<_, [u8; 64], _>(
            TwoFoldsProver::default(),
            dsfs::Keccak::default(),
        );
        let reduction_verifier = dsfs::reduction_verifier::<_, [u8; 64], _>(
            TwoFoldsVerifier::default(),
            dsfs::Keccak::default(),
        );
        assert_nir_prover(&reduction_prover);
        assert_nir_verifier(&reduction_verifier);
    }

    #[test]
    fn composition_uses_separate_prover_and_verifier_halves() {
        let n = 8;
        let values: Vec<Fr> = (0..n as u64).map(Fr::from).collect();
        let instance = Claims(values.clone());
        let witness = Values(values);

        let session = spongefish::session!("argus example: composition role split");
        let prover = dsfs::argument_prover(FullProtocolProver::default(), dsfs::Keccak::default());
        let verifier =
            dsfs::argument_verifier(FullProtocolVerifier::default(), dsfs::Keccak::default());

        assert_narg_prover(&prover);
        assert_narg_verifier(&verifier);

        let proof = prover.prove(&session, &instance, &witness);
        assert!(!proof.is_empty());

        verifier
            .verify(&session, &instance, &proof)
            .expect("separate composed verifier accepts prover proof");
    }

    #[test]
    fn composed_reduction_uses_separate_prover_and_verifier_halves() {
        let n = 8;
        let values: Vec<Fr> = (0..n as u64).map(Fr::from).collect();
        let instance = Claims(values.clone());
        let witness = Values(values);

        let session = spongefish::session!("argus example: composition reduction role split");
        let prover = dsfs::reduction_prover::<_, [u8; 64], _>(
            TwoFoldsProver::default(),
            dsfs::Keccak::default(),
        );
        let verifier = dsfs::reduction_verifier::<_, [u8; 64], _>(
            TwoFoldsVerifier::default(),
            dsfs::Keccak::default(),
        );

        assert_nir_prover(&prover);
        assert_nir_verifier(&verifier);

        let (proof, target_prover, _) = prover.prove(&session, &instance, &witness);
        assert!(!proof.is_empty());

        let target_verifier = verifier
            .verify(&session, &instance, &proof)
            .expect("separate composed reduction verifier accepts prover proof");

        assert_eq!(target_prover.0, target_verifier.0);
    }
}
