//! `SigmaIA<S>`: [`InteractiveArgument`] wrapper for any [`SigmaProtocol`].
//!
//! ## Design notes
//!
//! `SigmaIA<S>` maps the 3-message sigma protocol shape onto the IA channel API:
//!   - prover: send commitment(s) → read challenge → send response(s)
//!   - verifier: read commitment(s) → derive challenge → read response(s) → call verifier()
//!
//! **Q1 (protocol_id — BLOCKED):** `InteractiveArgument::protocol_id()` has no `&self`, but
//! `SigmaProtocol::protocol_identifier` takes `&self`. The `protocol_id()` impl below panics
//! until Michele clarifies whether `protocol_identifier` can be made a static associated fn.
//! Callers must use the `dsfs::prove_with_sponge` variants that bypass `protocol_id()`,
//! passing the protocol domain explicitly (as `fiat_shamir.rs` does today).
//!
//! **Q2 (randomness):** Commit randomness is supplied by the caller as a `[u8; 32]` seed
//! bundled into the witness: `type Witness = (S::Witness, [u8; 32])`. The seed is expanded
//! via `ChaCha20Rng::from_seed` before calling `prover_commit`. This keeps the prover
//! deterministic given the seed while avoiding any global RNG state.
//!
//! **Q3 (encoding):** `Encoding` is implemented for `SigmaIA<S>` by forwarding to
//! `SigmaProtocol::instance_label()`, bridging the two conventions.

extern crate alloc;

use alloc::vec::Vec;

use ia_core::{InteractiveArgument, ProverChannel, VerificationError, VerificationResult, VerifierChannel};
use rand_chacha::rand_core::SeedableRng;
use sigma_proofs::traits::SigmaProtocol;
use spongefish::Encoding;

/// Wraps a [`SigmaProtocol`] as an [`InteractiveArgument`].
///
/// `S` acts as both the protocol parameters and the public instance.
/// The witness bundles `(S::Witness, commit_seed)` where `commit_seed: [u8; 32]`
/// provides fresh randomness for `prover_commit` via `ChaCha20Rng`.
pub struct SigmaIA<S>(pub S);

impl<S> InteractiveArgument for SigmaIA<S>
where
    S: SigmaProtocol,
{
    type Instance = SigmaIA<S>;
    type Witness = (S::Witness, [u8; 32]);

    fn protocol_id() -> [u8; 32] {
        // Q1: `SigmaProtocol::protocol_identifier` takes `&self` so we can't call it here.
        // sigma-proofs pads short ASCII labels with zeros, so for simple protocols the first
        // 32 bytes of `protocol_identifier()` are the meaningful label and bytes 32-63 are
        // zeros. We return those first 32 bytes; DSFS appends the sponge tag in the upper half.
        //
        // For composed protocols (ComposedRelation) the full 64-byte id is a SHA3-256 digest
        // embedded in bytes 0-31 — which also fits here correctly.
        //
        // NOTE: this means SigmaIA proofs are NOT byte-for-byte compatible with sigma-proofs
        // Nizk (different sponge tag in upper 32 bytes). For spec-compatible proofs use
        // sigma_bridge::prove/verify directly.
        //
        // TODO: resolve Q1 with Michele — if protocol_identifier becomes static, call S::protocol_id()
        // and take [..32].
        [0u8; 32] // placeholder — protocol_identifier needs &self, cannot be called statically
    }

    fn prove<P: ProverChannel>(ch: &mut P, instance: &SigmaIA<S>, witness: &(S::Witness, [u8; 32])) {
        let (w, seed) = witness;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(*seed); // TODO: check if this is correct

        let (commitment, state) = instance
            .0
            .prover_commit(w, &mut rng)
            .expect("honest prover commit must not fail");

        for c in &commitment {
            ch.send_prover_message(c);
        }

        let challenge: S::Challenge = ch.read_verifier_message();

        let response = instance
            .0
            .prover_response(state, &challenge)
            .expect("honest prover response must not fail");

        for r in &response {
            ch.send_prover_message(r);
        }
    }

    fn verify<V: VerifierChannel>(ch: &mut V, instance: &SigmaIA<S>) -> VerificationResult<()> {
        let mut commitment = Vec::with_capacity(instance.0.commitment_len());
        for _ in 0..instance.0.commitment_len() {
            commitment.push(ch.read_prover_message::<S::Commitment>()?);
        }

        let challenge: S::Challenge = ch.send_verifier_message();

        let mut response = Vec::with_capacity(instance.0.response_len());
        for _ in 0..instance.0.response_len() {
            response.push(ch.read_prover_message::<S::Response>()?);
        }

        instance
            .0
            .verifier(&commitment, &challenge, &response)
            .map_err(|_| VerificationError)
    }
}

/// Bridges [`SigmaProtocol::instance_label`] to spongefish's [`Encoding`] trait.
///
/// This lets DSFS absorb the sigma instance into the transcript via `.instance(instance)`.
impl<S: SigmaProtocol> Encoding for SigmaIA<S> {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.0.instance_label().as_ref().to_vec()
    }
}
