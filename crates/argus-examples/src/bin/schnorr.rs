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
use ark_std::UniformRand;
use rand::rngs::OsRng;

use ia_core::{
    Decoding, Encoding, InteractiveArgument, NargDeserialize, Prove, Verify, VerificationError,
    VerificationResult,
};

// ---------------------------------------------------------------------------
// Protocol type
// ---------------------------------------------------------------------------

struct Schnorr<G: CurveGroup>(core::marker::PhantomData<G>);

impl<G: CurveGroup> InteractiveArgument for Schnorr<G> {
    type Instance = [G; 2]; // [generator, public_key]
    type Witness = G::ScalarField;

    fn protocol_id() -> [u8; 64] {
        spongefish::protocol_id(core::format_args!("schnorr proof"))
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
    G: CurveGroup + PrimeGroup + Encoding + NargDeserialize,
    G::ScalarField: Encoding + Decoding + NargDeserialize,
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
