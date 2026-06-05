//! Asymmetric DSFS compilation and role-view adapters.
//!
//! This file intentionally shows both patterns:
//!
//! 1. `FullEcho.into_prover()` / `FullEcho.into_verifier()` are ergonomic role
//!    views over a full body. They hide the opposite executable method at the
//!    wrapper type, but the wrapped body still implements both halves.
//! 2. `ProverOnlyEcho` and `VerifierOnlyEcho` are genuinely asymmetric bodies:
//!    each implements only one interactive half. This is the recursion-relevant
//!    capability decided at the 2026-06-05 meeting.
//!
//! Both paths compile through DSFS and preserve proof bytes. `CombinedNarg` glues
//! independently-built non-interactive halves back into a full non-interactive
//! argument, guarding that they agree on `protocol_id`.

use ia_core::prelude::*;
use ia_core::{
    pad_protocol_id, ArgumentCore, CombinedIA, ProtocolCore, VerificationError, VerificationResult,
};
use spongefish_dsfs::{plain_non_interactive_argument, CombinedNarg, Keccak};

// A one-message echo argument: the prover sends the witness; the verifier accepts
// iff that message equals the instance. The protocol body is identical across the
// three types below — only *which halves* they implement differs.
const ECHO_ID: &[u8] = b"asym-echo";

fn echo_prove<P: ProverChannel<Unit = u8>>(ch: &mut P, _instance: &[u8; 1], witness: &[u8; 1]) {
    ch.send_prover_message(witness);
}

fn echo_verify<V: VerifierChannel<Unit = u8>>(
    ch: &mut V,
    instance: &[u8; 1],
) -> VerificationResult<()> {
    let msg: [u8; 1] = ch.read_prover_message()?;
    if msg == *instance {
        Ok(())
    } else {
        Err(VerificationError)
    }
}

/// Full body: implements both halves.
struct FullEcho;
impl ProtocolCore for FullEcho {
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        pad_protocol_id(ECHO_ID)
    }
}
impl ArgumentCore for FullEcho {
    type Instance = [u8; 1];
    type Witness = [u8; 1];
}
impl InteractiveArgumentProver for FullEcho {
    fn prove<P: ProverChannel<Unit = u8>>(&self, ch: &mut P, x: &[u8; 1], w: &[u8; 1]) {
        echo_prove(ch, x, w)
    }
}
impl InteractiveArgumentVerifier for FullEcho {
    fn verify<V: VerifierChannel<Unit = u8>>(
        &self,
        ch: &mut V,
        x: &[u8; 1],
    ) -> VerificationResult<()> {
        echo_verify(ch, x)
    }
}

/// Prover-only body: implements `InteractiveArgumentProver` and *not* the verifier
/// half. It still compiles through DSFS — as a prover-only object.
struct ProverOnlyEcho;
impl ProtocolCore for ProverOnlyEcho {
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        pad_protocol_id(ECHO_ID)
    }
}
impl ArgumentCore for ProverOnlyEcho {
    type Instance = [u8; 1];
    type Witness = [u8; 1];
}
impl InteractiveArgumentProver for ProverOnlyEcho {
    fn prove<P: ProverChannel<Unit = u8>>(&self, ch: &mut P, x: &[u8; 1], w: &[u8; 1]) {
        echo_prove(ch, x, w)
    }
}

/// Verifier-only body: implements only `InteractiveArgumentVerifier`.
struct VerifierOnlyEcho;
impl ProtocolCore for VerifierOnlyEcho {
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        pad_protocol_id(ECHO_ID)
    }
}
impl ArgumentCore for VerifierOnlyEcho {
    type Instance = [u8; 1];
    type Witness = [u8; 1];
}
impl InteractiveArgumentVerifier for VerifierOnlyEcho {
    fn verify<V: VerifierChannel<Unit = u8>>(
        &self,
        ch: &mut V,
        x: &[u8; 1],
    ) -> VerificationResult<()> {
        echo_verify(ch, x)
    }
}

/// Verifier-only body with a *different* protocol id, to trip the recombine guard.
struct WrongIdVerifier;
impl ProtocolCore for WrongIdVerifier {
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        pad_protocol_id(b"asym-echo-WRONG")
    }
}
impl ArgumentCore for WrongIdVerifier {
    type Instance = [u8; 1];
    type Witness = [u8; 1];
}
impl InteractiveArgumentVerifier for WrongIdVerifier {
    fn verify<V: VerifierChannel<Unit = u8>>(
        &self,
        ch: &mut V,
        x: &[u8; 1],
    ) -> VerificationResult<()> {
        echo_verify(ch, x)
    }
}

const SESSION: [u8; 1] = [9];
const INSTANCE: [u8; 1] = [7];
const WITNESS: [u8; 1] = [7];

#[test]
fn role_views_from_full_body_compile_separately() {
    // Role views start from a full body. They are ergonomic method-boundary
    // wrappers, not proof that the verifier algorithm has no prover dependency.
    let full =
        plain_non_interactive_argument::<FullEcho, [u8; 1], Keccak>(FullEcho, Keccak::default());
    let proof_full = full.prove(&SESSION, &INSTANCE, &WITNESS);

    let prover = plain_non_interactive_argument::<_, [u8; 1], Keccak>(
        FullEcho.into_prover(),
        Keccak::default(),
    );
    let verifier = plain_non_interactive_argument::<_, [u8; 1], Keccak>(
        FullEcho.into_verifier(),
        Keccak::default(),
    );

    let proof_role_view = prover.prove(&SESSION, &INSTANCE, &WITNESS);
    assert_eq!(
        proof_role_view.as_bytes(),
        proof_full.as_bytes(),
        "role-view proof bytes must equal the full-compile proof",
    );

    verifier
        .verify(&SESSION, &INSTANCE, &proof_role_view)
        .expect("verifier role view accepts prover role-view proof");
}

#[test]
fn prover_only_and_verifier_only_match_the_full_compile() {
    // Full compile: prove + verify both available.
    let full =
        plain_non_interactive_argument::<FullEcho, [u8; 1], Keccak>(FullEcho, Keccak::default());
    let proof_full = full.prove(&SESSION, &INSTANCE, &WITNESS);
    full.verify(&SESSION, &INSTANCE, &proof_full)
        .expect("full compile verifies");

    // Prover-only body compiles to a prover-only object and produces the *same* bytes.
    let prover_only = plain_non_interactive_argument::<ProverOnlyEcho, [u8; 1], Keccak>(
        ProverOnlyEcho,
        Keccak::default(),
    );
    let proof_po = prover_only.prove(&SESSION, &INSTANCE, &WITNESS);
    assert_eq!(
        proof_po.as_bytes(),
        proof_full.as_bytes(),
        "prover-only proof bytes must equal the full-compile proof (no transcript drift)",
    );

    // Verifier-only body compiles to a verifier-only object and accepts that proof.
    let verifier_only = plain_non_interactive_argument::<VerifierOnlyEcho, [u8; 1], Keccak>(
        VerifierOnlyEcho,
        Keccak::default(),
    );
    verifier_only
        .verify(&SESSION, &INSTANCE, &proof_po)
        .expect("verifier-only verifies the prover-only proof");
}

#[test]
fn combined_narg_glues_independent_halves() {
    let combined = CombinedNarg::new(
        plain_non_interactive_argument::<ProverOnlyEcho, [u8; 1], Keccak>(
            ProverOnlyEcho,
            Keccak::default(),
        ),
        plain_non_interactive_argument::<VerifierOnlyEcho, [u8; 1], Keccak>(
            VerifierOnlyEcho,
            Keccak::default(),
        ),
    );
    // The recombined object is a full non-interactive argument: prove then verify.
    let proof = combined.prove(&SESSION, &INSTANCE, &WITNESS);
    combined
        .verify(&SESSION, &INSTANCE, &proof)
        .expect("recombined prover+verifier round-trips");

    // A wrong instance is rejected, confirming the verifier half is really wired in.
    let bad_instance = [42u8; 1];
    assert!(combined.verify(&SESSION, &bad_instance, &proof).is_err());
}

#[test]
#[should_panic(expected = "protocol_id")]
fn combined_narg_rejects_mismatched_protocol_id() {
    // Prover and verifier compiled from bodies with different protocol ids: the
    // debug-mode guard in `CombinedNarg::new` must trip.
    let _ = CombinedNarg::new(
        plain_non_interactive_argument::<ProverOnlyEcho, [u8; 1], Keccak>(
            ProverOnlyEcho,
            Keccak::default(),
        ),
        plain_non_interactive_argument::<WrongIdVerifier, [u8; 1], Keccak>(
            WrongIdVerifier,
            Keccak::default(),
        ),
    );
}

#[test]
fn combined_ia_glues_bodies_before_dsfs() {
    // The body-level mirror of `CombinedNarg`: glue a prover-only body and a
    // verifier-only body into one full interactive body, *then* compile it.
    let full_body = CombinedIA::new(ProverOnlyEcho, VerifierOnlyEcho);
    let nia = plain_non_interactive_argument::<
        CombinedIA<ProverOnlyEcho, VerifierOnlyEcho>,
        [u8; 1],
        Keccak,
    >(full_body, Keccak::default());

    let proof = nia.prove(&SESSION, &INSTANCE, &WITNESS);
    nia.verify(&SESSION, &INSTANCE, &proof)
        .expect("CombinedIA body round-trips through DSFS");

    // Same protocol id + same prove body ⇒ byte-identical to the monolithic compile.
    let full =
        plain_non_interactive_argument::<FullEcho, [u8; 1], Keccak>(FullEcho, Keccak::default());
    let proof_full = full.prove(&SESSION, &INSTANCE, &WITNESS);
    assert_eq!(
        proof.as_bytes(),
        proof_full.as_bytes(),
        "CombinedIA proof must equal the monolithic full-body proof",
    );
}

#[test]
#[should_panic(expected = "protocol_id")]
fn combined_ia_rejects_mismatched_protocol_id() {
    // Two bodies with different protocol ids glued at the body level: the
    // `CombinedIA::new` guard must trip.
    let _ = CombinedIA::new(ProverOnlyEcho, WrongIdVerifier);
}
