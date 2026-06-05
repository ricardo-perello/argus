//! Schnorr proof of knowledge.
//!
//! Proves knowledge of x such that X = x * G for public (G, X).
//!
//! Protocol:
//!   Prover sends  commitment  K = k * G
//!   Verifier sends challenge  c (scalar)
//!   Prover sends  response    r = k + c * x
//!   Verify: G * r == K + X * c
//!
//! Modes:
//!   (default)  Non-interactive via DSFS (Fiat-Shamir)
//!   --live     Interactive via live-channel (two threads, mpsc)

use std::thread;

use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::PrimeField;
use ark_std::UniformRand;
use rand::rngs::OsRng;
use spongefish_dsfs as dsfs;

use ia_core::prelude::*;
use ia_core::{
    ArgumentSecurity, Decoding, Deserialize, Encoding, ProverChannel, SecurityErrorBound,
    SecurityProfile, VerificationError, VerificationResult, VerifierChannel,
};

// ---------------------------------------------------------------------------
// Protocol type
// ---------------------------------------------------------------------------

struct Schnorr<G: CurveGroup>(core::marker::PhantomData<G>);

impl<G: CurveGroup> Default for Schnorr<G> {
    fn default() -> Self {
        Self(core::marker::PhantomData)
    }
}

ia_core::impl_interactive_argument! {
    impl<G> InteractiveArgument for Schnorr<G>
    where
        G: CurveGroup + PrimeGroup + Encoding + Deserialize,
        G::ScalarField: PrimeField + Encoding + Decoding + Deserialize,
    {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            ia_core::pad_protocol_id(b"schnorr")
        }

        /// [generator, public_key]
        type Instance = [G; 2];
        type Witness = G::ScalarField;

        #[allow(non_snake_case)]
        fn prove<P: ProverChannel<Unit = u8>>(&self, ch: &mut P, instance: &[G; 2], witness: &G::ScalarField) {
            let k = G::ScalarField::rand(&mut OsRng);
            let K = instance[0] * k;

            ch.send_prover_message(&K);
            let c: G::ScalarField = ch.read_verifier_message();
            let r = k + c * witness;
            ch.send_prover_message(&r);
        }

        #[allow(non_snake_case)]
        fn verify<V: VerifierChannel<Unit = u8>>(&self, ch: &mut V, instance: &[G; 2]) -> VerificationResult<()> {
            let (G_gen, X) = (instance[0], instance[1]);

            let K: G = ch.read_prover_message()?;
            let c: G::ScalarField = ch.send_verifier_message();
            let r: G::ScalarField = ch.read_prover_message()?;

            if G_gen * r == K + X * c {
                Ok(())
            } else {
                Err(VerificationError)
            }
        }
    }
}

impl<G> ArgumentSecurity for Schnorr<G>
where
    G: CurveGroup + PrimeGroup + Encoding + Deserialize,
    G::ScalarField: PrimeField + Encoding + Decoding + Deserialize,
{
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
        fn one_over_q<F: PrimeField>(_t: u64) -> f64 {
            2_f64.powi(-(F::MODULUS_BIT_SIZE as i32))
        }

        SecurityProfile {
            // Plain soundness: cheating prover guesses the challenge: 1/q.
            plain_soundness_error: SecurityErrorBound::new(one_over_q::<G::ScalarField>),
            // 1 round, RBR error = 1/q (SR soundness derived as sum = 1/q).
            rbr_soundness_errors: vec![SecurityErrorBound::new(one_over_q::<G::ScalarField>)],
            // Special soundness extractor succeeds except with prob 1/q.
            rbr_knowledge_soundness_errors: vec![SecurityErrorBound::new(
                one_over_q::<G::ScalarField>,
            )],
            // Perfect HVZK (simulator picks c first, computes K = rG - cX).
            hvzk_error: SecurityErrorBound::zero(),
            verifier_challenge_lengths: vec![1],
        }
    }
}

// ---------------------------------------------------------------------------
// DSFS mode: non-interactive prove + verify
// ---------------------------------------------------------------------------

fn run_dsfs(instance: &[ark_curve25519::EdwardsProjective; 2], sk: &ark_curve25519::Fr) {
    type G = ark_curve25519::EdwardsProjective;

    println!("=== Schnorr (DSFS / non-interactive) ===\n");

    let session = spongefish::session!("spongefish examples");

    let schnorr = Schnorr::<G>::default();
    let nia_schnorr = dsfs::plain_non_interactive_argument(schnorr, dsfs::Keccak::default());
    let narg_string = nia_schnorr.prove(&session, instance, sk);
    println!("Proof:\n{}", hex::encode(narg_string.as_bytes()));

    nia_schnorr
        .verify(&session, instance, &narg_string)
        .expect("verification failed");
    println!("Verification succeeded");
}

// ---------------------------------------------------------------------------
// Live mode: interactive prove + verify in two threads
// ---------------------------------------------------------------------------

fn run_live(instance: [ark_curve25519::EdwardsProjective; 2], sk: ark_curve25519::Fr) {
    type G = ark_curve25519::EdwardsProjective;

    println!("=== Schnorr (live / interactive) ===\n");

    let (mut prover_ch, mut verifier_ch) = live_channel::channel_pair();

    let prover_instance = instance;
    let prover_handle = thread::spawn(move || {
        Schnorr::<G>::default().prove(&mut prover_ch, &prover_instance, &sk);
        println!("[Prover]   Done.");
    });

    let verifier_instance = instance;
    let verifier_handle = thread::spawn(move || {
        let result = Schnorr::<G>::default().verify(&mut verifier_ch, &verifier_instance);
        match result {
            Ok(()) => println!("[Verifier] Verification succeeded!"),
            Err(_) => println!("[Verifier] Verification FAILED."),
        }
        result
    });

    prover_handle.join().unwrap();
    verifier_handle
        .join()
        .unwrap()
        .expect("live verification failed");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    type G = ark_curve25519::EdwardsProjective;
    type F = ark_curve25519::Fr;

    let generator = G::generator();
    let sk = F::rand(&mut OsRng);
    let pk = generator * sk;
    let instance = [generator, pk];

    let live = std::env::args().any(|a| a == "--live");

    if live {
        run_live(instance, sk);
    } else {
        run_dsfs(&instance, &sk);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::PrimeField;
    use ia_core::{
        ArgumentSecurity, IntoProver, IntoVerifier, NonInteractiveArgument,
        NonInteractiveArgumentProver, NonInteractiveArgumentVerifier,
    };
    use spongefish_dsfs::STD_SPONGE_PARAMS;
    use std::thread;

    type G = ark_curve25519::EdwardsProjective;
    type F = ark_curve25519::Fr;

    fn assert_narg_prover<N: NonInteractiveArgumentProver>(_: &N) {}

    fn assert_narg_verifier<N: NonInteractiveArgumentVerifier>(_: &N) {}

    #[test]
    fn schnorr_ia_soundness_is_one_over_q() {
        let schnorr = Schnorr::<G>::default();
        let instance = [G::generator(), G::generator()];
        let profile = schnorr.profile_for_concrete_instance(&instance);
        let expected = 2_f64.powi(-(F::MODULUS_BIT_SIZE as i32));

        // Plain soundness = 1/q
        let eps_plain = profile.plain_soundness_error.evaluate(0);
        assert!(
            (eps_plain - expected).abs() < 1e-30,
            "IA plain soundness should be 1/q = 2^-{}, got {eps_plain}",
            F::MODULUS_BIT_SIZE,
        );

        // SR soundness at t=0: (0 * 1/q) + 1/q = 1/q
        let eps_sr = profile.sr_soundness_error(0);
        assert!(
            (eps_sr - expected).abs() < 1e-30,
            "IA SR soundness should be 1/q = 2^-{}, got {eps_sr}",
            F::MODULUS_BIT_SIZE,
        );
    }

    #[test]
    fn schnorr_ia_hvzk_is_zero() {
        let schnorr = Schnorr::<G>::default();
        let instance = [G::generator(), G::generator()];
        let profile = schnorr.profile_for_concrete_instance(&instance);
        assert_eq!(profile.hvzk_error.evaluate(0), 0.0);
        assert_eq!(profile.hvzk_error.evaluate(1 << 40), 0.0);
    }

    #[test]
    fn schnorr_narg_soundness_adds_sponge_term() {
        let schnorr = Schnorr::<G>::default();
        let instance = [G::generator(), G::generator()];
        let narg = dsfs::security_for_concrete_instance(&schnorr, &instance);

        let t: u64 = 1 << 40;
        let t_f = t as f64;

        // 1 round, rbr = 1/q. SR formula (CY24 Thm 31.2.1): t * (1/q) + (1/q) = (t+1)/q
        let one_over_q = 2_f64.powi(-(F::MODULUS_BIT_SIZE as i32));
        let eps_sr = (t_f + 1.0) * one_over_q;
        let sp = STD_SPONGE_PARAMS;
        let sponge_term = 25.0 * t_f * t_f / sp.alphabet_size.powf(sp.capacity as f64);
        let expected = eps_sr + sponge_term;

        let got = narg.soundness_error(t);
        assert!(
            (got - expected).abs() / expected < 1e-10,
            "NARG soundness: expected {expected}, got {got}",
        );
    }

    #[test]
    fn schnorr_narg_soundness_bits_above_128() {
        let schnorr = Schnorr::<G>::default();
        let instance = [G::generator(), G::generator()];
        let narg = dsfs::security_for_concrete_instance(&schnorr, &instance);
        let t: u64 = 1 << 40;
        let bits = narg.soundness_bits(t);
        assert!(
            bits > 128.0,
            "Schnorr over curve25519 with Keccak should have >128-bit soundness, got {bits:.1}",
        );
    }

    #[test]
    fn schnorr_narg_zk_is_purely_sponge() {
        let schnorr = Schnorr::<G>::default();
        let instance = [G::generator(), G::generator()];
        let narg = dsfs::security_for_concrete_instance(&schnorr, &instance);
        let t: u64 = 1 << 40;
        let t_f = t as f64;

        let sp = STD_SPONGE_PARAMS;
        // z_IP = 0, so z_NARG(t) = t/|Sigma|^min(delta,c) + t*ceil(l_V/r)/|Sigma|^(r+c)
        let min_dc = sp.delta.min(sp.capacity);
        let term1 = t_f / sp.alphabet_size.powf(min_dc as f64);
        let ceil_lv_r = (1_u64).div_ceil(sp.rate);
        let term2 = t_f * ceil_lv_r as f64 / sp.alphabet_size.powf((sp.rate + sp.capacity) as f64);
        let expected = term1 + term2;

        let got = narg.zk_error(t);
        assert!(
            (got - expected).abs() / expected < 1e-10,
            "NARG ZK: expected {expected}, got {got}",
        );
    }

    #[test]
    fn schnorr_dsfs_roundtrip() {
        let generator = G::generator();
        let sk = F::rand(&mut OsRng);
        let pk = generator * sk;
        let instance = [generator, pk];

        let session = spongefish::session!("spongefish examples");
        let schnorr = Schnorr::<G>::default();
        let nia = dsfs::plain_non_interactive_argument(schnorr, dsfs::Keccak::default());
        let narg = nia.prove(&session, &instance, &sk);
        nia.verify(&session, &instance, &narg)
            .expect("dsfs verification failed");
    }

    #[test]
    fn schnorr_dsfs_separate_prover_and_verifier_halves_roundtrip() {
        let generator = G::generator();
        let sk = F::rand(&mut OsRng);
        let pk = generator * sk;
        let instance = [generator, pk];

        let session = spongefish::session!("spongefish examples");
        let prover = dsfs::plain_non_interactive_argument(
            Schnorr::<G>::default().into_prover(),
            dsfs::Keccak::default(),
        );
        let verifier = dsfs::plain_non_interactive_argument(
            Schnorr::<G>::default().into_verifier(),
            dsfs::Keccak::default(),
        );

        assert_narg_prover(&prover);
        assert_narg_verifier(&verifier);

        let proof = prover.prove(&session, &instance, &sk);
        assert!(!proof.is_empty());

        verifier
            .verify(&session, &instance, &proof)
            .expect("separately compiled Schnorr verifier accepted prover proof");
    }

    #[test]
    fn schnorr_dsfs_wrapper_is_non_interactive_argument() {
        let generator = G::generator();
        let sk = F::rand(&mut OsRng);
        let pk = generator * sk;
        let instance = [generator, pk];

        let session = spongefish::session!("spongefish examples");
        let schnorr = Schnorr::<G>::default();
        let narg = dsfs::plain_non_interactive_argument(schnorr, dsfs::Keccak::default());
        fn assert_narg<N: NonInteractiveArgument>(_: &N) {}
        assert_narg(&narg);

        let proof = narg.prove(&session, &instance, &sk);

        assert!(!proof.is_empty());
        narg.verify(&session, &instance, &proof)
            .expect("DSFS-backed NARG verification failed");
    }

    #[test]
    fn schnorr_live_roundtrip() {
        let generator = G::generator();
        let sk = F::rand(&mut OsRng);
        let pk = generator * sk;
        let instance = [generator, pk];

        let (mut prover_ch, mut verifier_ch) = live_channel::channel_pair();

        let prover_instance = instance;
        let prover_handle = thread::spawn(move || {
            Schnorr::<G>::default().prove(&mut prover_ch, &prover_instance, &sk);
        });

        let verifier_instance = instance;
        let verifier_handle = thread::spawn(move || {
            Schnorr::<G>::default().verify(&mut verifier_ch, &verifier_instance)
        });

        prover_handle.join().unwrap();
        verifier_handle
            .join()
            .unwrap()
            .expect("live verification failed");
    }
}
