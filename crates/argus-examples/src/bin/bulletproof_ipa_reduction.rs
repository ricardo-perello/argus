//! Bulletproofs IPA — the reduction view.
//!
//! The monolithic IPA loop (see `bulletproof_ipa`) is exactly `log2(n)` copies
//! of one reduction. This example expresses that directly:
//!
//! - `IpaFold` — an `InteractiveReduction` with `Source = Target =
//!   IpaInstance<G>` performing one round (`n -> n/2`).
//! - `IpaBase` — an `InteractiveArgument` that decides the size-1 statement.
//!
//! For `n = 8` they compose statically (mirroring the `composition` example):
//!
//! ```text
//!   ReducedArgument<Fold . Fold . Fold, Base>   (8 -> 4 -> 2 -> 1 -> accept)
//! ```
//!
//! `ChainedReduction` / `ReducedArgument` are static composition, so the fold
//! depth is fixed to the chosen `n`; general `n` would need a runtime loop
//! driver. Run with:
//!
//!   cargo run -p argus-examples --bin bulletproof_ipa_reduction

use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{Field, PrimeField};
use rand::rngs::OsRng;
use spongefish_dsfs as dsfs;

use argus_examples::bulletproofs::{
    IpaInstance, IpaWitness, inner_product, ipa_round_error, msm, random_statement,
};
use ia_core::prelude::*;
use ia_core::{
    ArgumentSecurity, ChainedReduction, Decoding, Deserialize, Encoding, ProverChannel,
    ReducedArgument, ReductionSecurity, SecurityErrorBound, SecurityProfile, VerificationError,
    VerificationResult, VerifierChannel,
};

// ---------------------------------------------------------------------------
// IpaFold: one folding round as a reduction (n -> n/2)
// ---------------------------------------------------------------------------

struct IpaFoldProver<G: CurveGroup>(core::marker::PhantomData<G>);
struct IpaFoldVerifier<G: CurveGroup>(core::marker::PhantomData<G>);

impl<G: CurveGroup> Default for IpaFoldProver<G> {
    fn default() -> Self {
        Self(core::marker::PhantomData)
    }
}

impl<G: CurveGroup> Default for IpaFoldVerifier<G> {
    fn default() -> Self {
        Self(core::marker::PhantomData)
    }
}

ia_core::impl_interactive_reduction_prover! {
    impl<G> for IpaFoldProver<G>
    where
        G: CurveGroup + PrimeGroup + Encoding + Deserialize,
        G::ScalarField: PrimeField + Encoding + Decoding + Deserialize,
    {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            ia_core::pad_protocol_id(b"bulletproofs-ipa-fold")
        }

        type SourceInstance = IpaInstance<G>;
        type TargetInstance = IpaInstance<G>;
        type SourceWitness = IpaWitness<G::ScalarField>;
        type TargetWitness = IpaWitness<G::ScalarField>;

        #[allow(non_snake_case)]
        fn prove<P: ProverChannel<Unit = u8>>(
            &self,
            ch: &mut P,
            instance: &IpaInstance<G>,
            witness: &IpaWitness<G::ScalarField>,
        ) -> (IpaInstance<G>, IpaWitness<G::ScalarField>) {
            let half = witness.a.len() / 2;
            let (a_lo, a_hi) = witness.a.split_at(half);
            let (b_lo, b_hi) = witness.b.split_at(half);
            let (g_lo, g_hi) = instance.g.split_at(half);
            let (h_lo, h_hi) = instance.h.split_at(half);
            let u = instance.u;

            let c_L = inner_product(a_lo, b_hi);
            let c_R = inner_product(a_hi, b_lo);
            let L = msm(a_lo, g_hi) + msm(b_hi, h_lo) + u * c_L;
            let R = msm(a_hi, g_lo) + msm(b_lo, h_hi) + u * c_R;

            ch.send_prover_message(&L);
            ch.send_prover_message(&R);
            let x: G::ScalarField = ch.read_verifier_message();
            let x_inv = x.inverse().expect("challenge must be non-zero");

            let a: Vec<_> = (0..half).map(|i| a_lo[i] * x + a_hi[i] * x_inv).collect();
            let b: Vec<_> = (0..half).map(|i| b_lo[i] * x_inv + b_hi[i] * x).collect();
            let g: Vec<_> = (0..half).map(|i| g_lo[i] * x_inv + g_hi[i] * x).collect();
            let h: Vec<_> = (0..half).map(|i| h_lo[i] * x + h_hi[i] * x_inv).collect();
            let p = L * x.square() + instance.p + R * x_inv.square();

            (IpaInstance { g, h, u, p }, IpaWitness { a, b })
        }

    }
}

ia_core::impl_interactive_reduction_verifier! {
    impl<G> for IpaFoldVerifier<G>
    where
        G: CurveGroup + PrimeGroup + Encoding + Deserialize,
        G::ScalarField: PrimeField + Encoding + Decoding + Deserialize,
    {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            ia_core::pad_protocol_id(b"bulletproofs-ipa-fold")
        }

        type SourceInstance = IpaInstance<G>;
        type TargetInstance = IpaInstance<G>;

        #[allow(non_snake_case)]
        fn verify<V: VerifierChannel<Unit = u8>>(
            &self,
            ch: &mut V,
            instance: &IpaInstance<G>,
        ) -> VerificationResult<IpaInstance<G>> {
            let half = instance.g.len() / 2;
            let (g_lo, g_hi) = instance.g.split_at(half);
            let (h_lo, h_hi) = instance.h.split_at(half);

            let L: G = ch.read_prover_message()?;
            let R: G = ch.read_prover_message()?;
            let x: G::ScalarField = ch.send_verifier_message();
            let x_inv = x.inverse().ok_or(VerificationError)?;

            let g: Vec<_> = (0..half).map(|i| g_lo[i] * x_inv + g_hi[i] * x).collect();
            let h: Vec<_> = (0..half).map(|i| h_lo[i] * x + h_hi[i] * x_inv).collect();
            let p = L * x.square() + instance.p + R * x_inv.square();

            Ok(IpaInstance { g, h, u: instance.u, p })
        }
    }
}

impl<G> ReductionSecurity for IpaFoldVerifier<G>
where
    G: CurveGroup + PrimeGroup + Encoding + Deserialize,
    G::ScalarField: PrimeField + Encoding + Decoding + Deserialize,
{
    type SourceParams = ();
    type SourceBound = ();
    type TargetBound = ();

    fn source_security_params(&self, _instance: &Self::SourceInstance) {}
    fn source_bound_for_source_params(&self, _params: &Self::SourceParams) {}
    fn target_bound_for_source_params(&self, _params: &Self::SourceParams) {}
    fn target_bound_for_source_bound(&self, _bound: &Self::SourceBound) {}

    fn profile_for_source_params(&self, _params: &Self::SourceParams) -> SecurityProfile {
        self.profile_for_source_bound(&())
    }

    fn profile_for_source_bound(&self, _bound: &Self::SourceBound) -> SecurityProfile {
        let per_round = ipa_round_error::<G::ScalarField>();
        SecurityProfile {
            plain_soundness_error: SecurityErrorBound::new(move |_t| per_round),
            rbr_soundness_errors: vec![SecurityErrorBound::new(move |_t| per_round)],
            rbr_knowledge_soundness_errors: vec![SecurityErrorBound::new(move |_t| per_round)],
            hvzk_error: SecurityErrorBound::zero(),
            verifier_challenge_lengths: vec![1],
        }
    }
}

// ---------------------------------------------------------------------------
// IpaBase: size-1 decider
// ---------------------------------------------------------------------------

struct IpaBaseProver<G: CurveGroup>(core::marker::PhantomData<G>);
struct IpaBaseVerifier<G: CurveGroup>(core::marker::PhantomData<G>);

impl<G: CurveGroup> Default for IpaBaseProver<G> {
    fn default() -> Self {
        Self(core::marker::PhantomData)
    }
}

impl<G: CurveGroup> Default for IpaBaseVerifier<G> {
    fn default() -> Self {
        Self(core::marker::PhantomData)
    }
}

ia_core::impl_interactive_argument_prover! {
    impl<G> for IpaBaseProver<G>
    where
        G: CurveGroup + PrimeGroup + Encoding + Deserialize,
        G::ScalarField: PrimeField + Encoding + Decoding + Deserialize,
    {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            ia_core::pad_protocol_id(b"bulletproofs-ipa-base")
        }

        type Instance = IpaInstance<G>;
        type Witness = IpaWitness<G::ScalarField>;

        fn prove<P: ProverChannel<Unit = u8>>(
            &self,
            ch: &mut P,
            _instance: &IpaInstance<G>,
            witness: &IpaWitness<G::ScalarField>,
        ) {
            assert_eq!(witness.a.len(), 1, "IpaBase expects a size-1 statement");
            ch.send_prover_message(&witness.a[0]);
            ch.send_prover_message(&witness.b[0]);
        }

    }
}

ia_core::impl_interactive_argument_verifier! {
    impl<G> for IpaBaseVerifier<G>
    where
        G: CurveGroup + PrimeGroup + Encoding + Deserialize,
        G::ScalarField: PrimeField + Encoding + Decoding + Deserialize,
    {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            ia_core::pad_protocol_id(b"bulletproofs-ipa-base")
        }

        type Instance = IpaInstance<G>;

        fn verify<V: VerifierChannel<Unit = u8>>(
            &self,
            ch: &mut V,
            instance: &IpaInstance<G>,
        ) -> VerificationResult<()> {
            if instance.g.len() != 1 {
                return Err(VerificationError);
            }
            let a: G::ScalarField = ch.read_prover_message()?;
            let b: G::ScalarField = ch.read_prover_message()?;
            if instance.p == instance.g[0] * a + instance.h[0] * b + instance.u * (a * b) {
                Ok(())
            } else {
                Err(VerificationError)
            }
        }
    }
}

impl<G> ArgumentSecurity for IpaBaseVerifier<G>
where
    G: CurveGroup + PrimeGroup + Encoding + Deserialize,
    G::ScalarField: PrimeField + Encoding + Decoding + Deserialize,
{
    type InstanceParams = ();
    type InstanceBound = ();

    fn instance_security_params(&self, _instance: &Self::Instance) {}
    fn instance_bound_for_instance_params(&self, _params: &Self::InstanceParams) {}

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

// Static composition for n = 8 (three folds: 8 -> 4 -> 2 -> 1, then decide).
type IpaFold2Prover<G> = ChainedReduction<IpaFoldProver<G>, IpaFoldProver<G>>;
type IpaFold3Prover<G> = ChainedReduction<IpaFold2Prover<G>, IpaFoldProver<G>>;
type ComposedIpaProver<G> = ReducedArgument<IpaFold3Prover<G>, IpaBaseProver<G>>;
type IpaFold2Verifier<G> = ChainedReduction<IpaFoldVerifier<G>, IpaFoldVerifier<G>>;
type IpaFold3Verifier<G> = ChainedReduction<IpaFold2Verifier<G>, IpaFoldVerifier<G>>;
type ComposedIpaVerifier<G> = ReducedArgument<IpaFold3Verifier<G>, IpaBaseVerifier<G>>;

// ---------------------------------------------------------------------------
// Demo
// ---------------------------------------------------------------------------

type Demo = ark_curve25519::EdwardsProjective;

fn main() {
    let n = 8;
    println!("=== Composed IPA: ReducedArgument<Fold.Fold.Fold, Base>, n = {n} ===\n");
    let (instance, witness) = random_statement::<Demo>(n, &mut OsRng);
    let session = spongefish::session!("bulletproofs ipa reduction example");
    let prover = dsfs::argument_prover(
        ComposedIpaProver::<Demo>::default(),
        dsfs::Keccak::default(),
    );
    let verifier = dsfs::argument_verifier(
        ComposedIpaVerifier::<Demo>::default(),
        dsfs::Keccak::default(),
    );
    let narg = prover.prove(&session, &instance, &witness);
    println!("Proof: {} bytes", narg.as_bytes().len());
    verifier
        .verify(&session, &instance, &narg)
        .expect("composed verification failed");
    println!("Verification succeeded (reduction form reproduces the monolithic loop)");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    type G = ark_curve25519::EdwardsProjective;

    #[test]
    fn composed_ipa_roundtrip() {
        let (instance, witness) = random_statement::<G>(8, &mut OsRng);
        let session = spongefish::session!("bulletproofs ipa reduction test");
        let prover =
            dsfs::argument_prover(ComposedIpaProver::<G>::default(), dsfs::Keccak::default());
        let verifier =
            dsfs::argument_verifier(ComposedIpaVerifier::<G>::default(), dsfs::Keccak::default());
        let narg = prover.prove(&session, &instance, &witness);
        verifier
            .verify(&session, &instance, &narg)
            .expect("composed verification failed");
    }

    #[test]
    fn composed_ipa_rejects_wrong_commitment() {
        let (mut instance, witness) = random_statement::<G>(8, &mut OsRng);
        instance.p += G::generator();
        let session = spongefish::session!("bulletproofs ipa reduction test");
        let prover =
            dsfs::argument_prover(ComposedIpaProver::<G>::default(), dsfs::Keccak::default());
        let verifier =
            dsfs::argument_verifier(ComposedIpaVerifier::<G>::default(), dsfs::Keccak::default());
        let narg = prover.prove(&session, &instance, &witness);
        assert!(verifier.verify(&session, &instance, &narg).is_err());
    }
}
