//! Schnorr proof of knowledge via the InteractiveArgument + DSFS stack.
//!
//! Proves knowledge of x such that X = x * G for public (G, X).
//!
//! Protocol (2 rounds, strict Construction 4.3):
//!   Round 0: Prover sends commitment K = k * G
//!            Verifier challenge c (scalar)
//!   Round 1: Prover sends response  r = k + c * x
//!            Verifier challenge (unused)
//!   Verify:  G * r == K + X * c

use ark_ec::{CurveGroup, PrimeGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use rand::rngs::OsRng;

use ia_core::{InteractiveArgument, Transcript};
use spongefish::{protocol_id, Encoding, NargDeserialize, VerificationError, VerificationResult};

// ---------------------------------------------------------------------------
// Protocol types
// ---------------------------------------------------------------------------

struct Schnorr<G: CurveGroup>(core::marker::PhantomData<G>);

enum SchnorrMsg<G: CurveGroup> {
    Commitment(G),
    Response(G::ScalarField),
}

struct SchnorrProverState<G: CurveGroup> {
    witness: G::ScalarField,
    k: G::ScalarField,
    generator: G,
    round: usize,
}

// ---------------------------------------------------------------------------
// Codec: Encoding + NargDeserialize for SchnorrMsg
// (NargSerialize is provided by a blanket impl over Encoding)
// ---------------------------------------------------------------------------

fn canonical_bytes<T: CanonicalSerialize>(v: &T) -> Vec<u8> {
    let mut buf = Vec::new();
    v.serialize_compressed(&mut buf).expect("serialization must succeed");
    buf
}

impl<G: CurveGroup> Encoding<[u8]> for SchnorrMsg<G>
where
    G: CanonicalSerialize,
    G::ScalarField: CanonicalSerialize,
{
    fn encode(&self) -> impl AsRef<[u8]> {
        match self {
            SchnorrMsg::Commitment(k) => {
                let mut buf = vec![0u8];
                buf.extend_from_slice(&canonical_bytes(k));
                buf
            }
            SchnorrMsg::Response(r) => {
                let mut buf = vec![1u8];
                buf.extend_from_slice(&canonical_bytes(r));
                buf
            }
        }
    }
}

impl<G: CurveGroup> NargDeserialize for SchnorrMsg<G>
where
    G: CanonicalDeserialize,
    G::ScalarField: CanonicalDeserialize,
{
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        if buf.is_empty() {
            return Err(VerificationError);
        }
        let tag = buf[0];
        *buf = &buf[1..];
        match tag {
            0 => {
                let k = G::deserialize_compressed(&mut *buf)
                    .map_err(|_| VerificationError)?;
                Ok(SchnorrMsg::Commitment(k))
            }
            1 => {
                let r = G::ScalarField::deserialize_compressed(&mut *buf)
                    .map_err(|_| VerificationError)?;
                Ok(SchnorrMsg::Response(r))
            }
            _ => Err(VerificationError),
        }
    }
}

// ---------------------------------------------------------------------------
// InteractiveArgument implementation
// ---------------------------------------------------------------------------

impl<G> InteractiveArgument for Schnorr<G>
where
    G: CurveGroup + CanonicalSerialize + CanonicalDeserialize,
    G::ScalarField: CanonicalSerialize + CanonicalDeserialize,
{
    type Instance = [G; 2]; // [generator, public_key]
    type Witness = G::ScalarField;
    type ProverState = SchnorrProverState<G>;
    type ProverMessage = SchnorrMsg<G>;
    type VerifierChallenge = G::ScalarField;

    fn protocol_id() -> [u8; 64] {
        protocol_id(core::format_args!("schnorr proof"))
    }

    fn num_rounds(_instance: &Self::Instance) -> usize {
        2
    }

    fn prover_init(instance: &Self::Instance, witness: &Self::Witness) -> Self::ProverState {
        SchnorrProverState {
            witness: *witness,
            k: G::ScalarField::rand(&mut OsRng),
            generator: instance[0],
            round: 0,
        }
    }

    #[allow(non_snake_case)]
    fn prover_round(
        state: &mut Self::ProverState,
        challenge: Option<&Self::VerifierChallenge>,
    ) -> Self::ProverMessage {
        let msg = match state.round {
            0 => {
                let K = state.generator * state.k;
                SchnorrMsg::Commitment(K)
            }
            1 => {
                let c = challenge.expect("round 1 requires a challenge");
                let r = state.k + *c * state.witness;
                SchnorrMsg::Response(r)
            }
            _ => panic!("Schnorr protocol has exactly 2 rounds"),
        };
        state.round += 1;
        msg
    }

    #[allow(non_snake_case)]
    fn verify(
        instance: &Self::Instance,
        transcript: &Transcript<Self::ProverMessage, Self::VerifierChallenge>,
    ) -> bool {
        if transcript.rounds.len() != 2 {
            return false;
        }

        let (G, X) = (instance[0], instance[1]);

        let K = match &transcript.rounds[0].message {
            SchnorrMsg::Commitment(k) => *k,
            _ => return false,
        };
        let c = transcript.rounds[0].challenge;

        let r = match &transcript.rounds[1].message {
            SchnorrMsg::Response(r) => *r,
            _ => return false,
        };

        G * r == K + X * c
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

    let proof = dsfs::prove::<Schnorr<G>>(session, &instance, &sk);
    println!("Schnorr proof (IA + DSFS):\n{}", hex::encode(&proof));

    dsfs::verify::<Schnorr<G>>(session, &instance, &proof).expect("verification failed");
    println!("Verification succeeded");
}
