//! Native asymmetric DSFS compilation.
//!
//! The prover and verifier are independent protocol roles. Neither role wraps a
//! full protocol body, and the compiled DSFS objects expose only their matching
//! non-interactive capability.

use ia_core::prelude::*;
use ia_core::{VerificationError, VerificationResult, pad_protocol_id};
use spongefish_dsfs::{
    Keccak, plain_non_interactive_argument_prover, plain_non_interactive_argument_verifier,
};

const ECHO_ID: &[u8] = b"asym-echo";

struct EchoProver;
struct EchoVerifier;

ia_core::impl_interactive_argument_prover! {
    impl for EchoProver {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            pad_protocol_id(ECHO_ID)
        }

        type Instance = [u8; 1];
        type Witness = [u8; 1];

        fn prove<P: ProverChannel<Unit = u8>>(
            &self,
            ch: &mut P,
            _instance: &[u8; 1],
            witness: &[u8; 1],
        ) {
            ch.send_prover_message(witness);
        }
    }
}

ia_core::impl_interactive_argument_verifier! {
    impl for EchoVerifier {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            pad_protocol_id(ECHO_ID)
        }

        type Instance = [u8; 1];

        fn verify<V: VerifierChannel<Unit = u8>>(
            &self,
            ch: &mut V,
            instance: &[u8; 1],
        ) -> VerificationResult<()> {
            let message: [u8; 1] = ch.read_prover_message()?;
            if message == *instance {
                Ok(())
            } else {
                Err(VerificationError)
            }
        }
    }
}

const SESSION: [u8; 1] = [9];
const INSTANCE: [u8; 1] = [7];
const WITNESS: [u8; 1] = [7];

fn assert_narg_prover<N: NonInteractiveArgumentProver>(_: &N) {}
fn assert_narg_verifier<N: NonInteractiveArgumentVerifier>(_: &N) {}

#[test]
fn native_roles_compile_and_roundtrip_independently() {
    let prover =
        plain_non_interactive_argument_prover::<_, [u8; 1], Keccak>(EchoProver, Keccak::default());
    let verifier = plain_non_interactive_argument_verifier::<_, [u8; 1], Keccak>(
        EchoVerifier,
        Keccak::default(),
    );

    assert_narg_prover(&prover);
    assert_narg_verifier(&verifier);

    let proof = prover.prove(&SESSION, &INSTANCE, &WITNESS);
    verifier
        .verify(&SESSION, &INSTANCE, &proof)
        .expect("native verifier accepts native prover proof");

    assert!(verifier.verify(&SESSION, &[42], &proof).is_err());
}

#[test]
fn native_role_proof_is_deterministic() {
    let prover =
        plain_non_interactive_argument_prover::<_, [u8; 1], Keccak>(EchoProver, Keccak::default());
    let first = prover.prove(&SESSION, &INSTANCE, &WITNESS);
    let second = prover.prove(&SESSION, &INSTANCE, &WITNESS);
    assert_eq!(first.as_bytes(), second.as_bytes());
}
