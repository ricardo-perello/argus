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

use ia_core::{
    Decoding, Deserialize, Encoding, InteractiveArgument, Prove, SecurityErrorBound,
    SecurityProfile, Verify, VerificationError, VerificationResult,
};

// ---------------------------------------------------------------------------
// Protocol type
// ---------------------------------------------------------------------------

struct Schnorr<G: CurveGroup>(core::marker::PhantomData<G>);

impl<G: CurveGroup> InteractiveArgument for Schnorr<G>
where
    G::ScalarField: PrimeField,
{
    type Instance = [G; 2]; // [generator, public_key]
    type Witness = G::ScalarField;

    fn protocol_id() -> [u8; 64] {
        spongefish::protocol_id(core::format_args!("schnorr proof"))
    }

    fn security() -> SecurityProfile {
        fn one_over_q<F: PrimeField>(_t: u64) -> f64 {
            2_f64.powi(-(F::MODULUS_BIT_SIZE as i32))
        }

        SecurityProfile {
            // Cheating prover guesses the challenge: ε^sr = 1/q.
            soundness_error: SecurityErrorBound::new(one_over_q::<G::ScalarField>),
            // Special soundness extractor succeeds except with prob 1/q.
            knowledge_soundness_error: SecurityErrorBound::new(one_over_q::<G::ScalarField>),
            // Perfect HVZK (simulator picks c first, computes K = rG - cX).
            hvzk_error: SecurityErrorBound::zero(),
            num_rounds: 1,
            verifier_challenge_lengths: vec![1],
        }
    }
}

// ---------------------------------------------------------------------------
// Prove: linear prover logic against an abstract channel
// ---------------------------------------------------------------------------

impl<G, P> Prove<P> for Schnorr<G>
where
    G: CurveGroup + PrimeGroup + Encoding,
    G::ScalarField: Encoding + Decoding,
    P: ia_core::ProverChannel,
{
    #[allow(non_snake_case)]
    fn prove(ch: &mut P, instance: &[G; 2], witness: &G::ScalarField) {
        let k = G::ScalarField::rand(&mut OsRng);
        let K = instance[0] * k;

        ch.send_prover_message(&K);
        let c: G::ScalarField = ch.read_verifier_message();
        let r = k + c * witness;
        ch.send_prover_message(&r);
    }
}

// ---------------------------------------------------------------------------
// Verify: linear verifier logic against an abstract channel
// ---------------------------------------------------------------------------

impl<G, V> Verify<V> for Schnorr<G>
where
    G: CurveGroup + PrimeGroup + Encoding + Deserialize,
    G::ScalarField: Encoding + Decoding + Deserialize,
    V: ia_core::VerifierChannel,
{
    #[allow(non_snake_case)]
    fn verify(ch: &mut V, instance: &[G; 2]) -> VerificationResult<()> {
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

// ---------------------------------------------------------------------------
// DSFS mode: non-interactive prove + verify
// ---------------------------------------------------------------------------

fn run_dsfs(instance: &[ark_curve25519::EdwardsProjective; 2], sk: &ark_curve25519::Fr) {
    type G = ark_curve25519::EdwardsProjective;

    println!("=== Schnorr (DSFS / non-interactive) ===\n");

    let session = spongefish::session!("spongefish examples");

    let narg_string = dsfs::prove::<Schnorr<G>>(session, instance, sk);
    println!("Proof:\n{}", hex::encode(&narg_string));

    dsfs::verify::<Schnorr<G>>(session, instance, &narg_string).expect("verification failed");
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
        Schnorr::<G>::prove(&mut prover_ch, &prover_instance, &sk);
        println!("[Prover]   Done.");
    });

    let verifier_instance = instance;
    let verifier_handle = thread::spawn(move || {
        let result = Schnorr::<G>::verify(&mut verifier_ch, &verifier_instance);
        match result {
            Ok(()) => println!("[Verifier] Verification succeeded!"),
            Err(_) => println!("[Verifier] Verification FAILED."),
        }
        result
    });

    prover_handle.join().unwrap();
    verifier_handle.join().unwrap().expect("live verification failed");
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
    use dsfs::STD_SPONGE_PARAMS;
    use ia_core::InteractiveArgument;

    type G = ark_curve25519::EdwardsProjective;
    type F = ark_curve25519::Fr;

    #[test]
    fn schnorr_ia_soundness_is_one_over_q() {
        let profile = Schnorr::<G>::security();
        let eps = profile.soundness_error.evaluate(0);
        let expected = 2_f64.powi(-(F::MODULUS_BIT_SIZE as i32));
        assert!(
            (eps - expected).abs() < 1e-30,
            "IA soundness should be 1/q = 2^-{}, got {eps}",
            F::MODULUS_BIT_SIZE,
        );
    }

    #[test]
    fn schnorr_ia_hvzk_is_zero() {
        let profile = Schnorr::<G>::security();
        assert_eq!(profile.hvzk_error.evaluate(0), 0.0);
        assert_eq!(profile.hvzk_error.evaluate(1 << 40), 0.0);
    }

    #[test]
    fn schnorr_narg_soundness_adds_sponge_term() {
        let narg = dsfs::security::<Schnorr<G>>();

        let t: u64 = 1 << 40;
        let t_f = t as f64;

        let eps_sr = 2_f64.powi(-(F::MODULUS_BIT_SIZE as i32));
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
        let narg = dsfs::security::<Schnorr<G>>();
        let t: u64 = 1 << 40;
        let bits = narg.soundness_bits(t);
        assert!(
            bits > 128.0,
            "Schnorr over curve25519 with Keccak should have >128-bit soundness, got {bits:.1}",
        );
    }

    #[test]
    fn schnorr_narg_zk_is_purely_sponge() {
        let narg = dsfs::security::<Schnorr<G>>();
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
}
