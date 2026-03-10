//! Schnorr proof of knowledge via the InteractiveArgument + DSFS stack (v2).
//!
//! Proves knowledge of x such that X = x * G for public (G, X).
//!
//! Protocol (linear channel):
//!   Prover sends  commitment  K = k * G
//!   Verifier sends challenge  c (scalar)
//!   Prover sends  response    r = k + c * x
//!   Verify: G * r == K + X * c

use ark_ec::{CurveGroup, PrimeGroup};
use ark_std::UniformRand;
use rand::rngs::OsRng;

use ia_core::{
    InteractiveArgument, Prove, ReadProverMessage, ReadVerifierMessage, SendProverMessage,
    SendVerifierMessage, Verify, VerificationError, VerificationResult,
};

// ---------------------------------------------------------------------------
// Protocol type
// ---------------------------------------------------------------------------

struct Schnorr<G: CurveGroup>(core::marker::PhantomData<G>);

// ---------------------------------------------------------------------------
// InteractiveArgument: metadata only
// ---------------------------------------------------------------------------

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
    G: CurveGroup + PrimeGroup,
    P: SendProverMessage<G> + SendProverMessage<G::ScalarField> + ReadVerifierMessage<G::ScalarField>,
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
    G: CurveGroup + PrimeGroup,
    V: ReadProverMessage<G>
        + ReadProverMessage<G::ScalarField>
        + SendVerifierMessage<G::ScalarField>,
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
// Main: prove and verify via DSFS
// ---------------------------------------------------------------------------

fn main() {
    type G = ark_curve25519::EdwardsProjective;
    type F = ark_curve25519::Fr;

    let generator = G::generator();
    let sk = F::rand(&mut OsRng);
    let pk = generator * sk;
    let instance = [generator, pk];

    let session = spongefish::session!("spongefish examples");

    let narg_string = dsfs::prove::<Schnorr<G>>(session, &instance, &sk);
    println!("Schnorr proof (IA v2 + DSFS):\n{}", hex::encode(&narg_string));

    dsfs::verify::<Schnorr<G>>(session, &instance, &narg_string).expect("verification failed");
    println!("Verification succeeded");
}
