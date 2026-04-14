//! `SigmaIA<S>`: [`InteractiveArgument`] wrapper for any [`SigmaProtocol`].
//!
//! ## Design notes
//!
//! `SigmaIA<S>` maps the 3-message sigma protocol shape onto the IA channel API:
//!   - prover: send commitment(s) → read challenge → send response(s)
//!   - verifier: read commitment(s) → derive challenge → read response(s) → call verifier()
//!
//! **Protocol id:** `protocol_identifier()` (64-byte sigma-proofs label or runtime hash for
//! compositions) is mixed with compilation info and session via spongefish
//! [`spongefish::DomainSeparator::derive`] in DSFS.
//!
//! Note: SigmaIA proofs are NOT byte-for-byte compatible with sigma-proofs `Nizk` (different
//! domain separator structure). For spec-compatible proofs use `sigma_bridge::prove/verify`.
//!
//! **Randomness:** Commit randomness is supplied as a `[u8; 32]` seed bundled into the
//! witness: `type Witness = (S::Witness, [u8; 32])`. The seed is expanded via
//! `ChaCha20Rng::from_seed` before calling `prover_commit`, keeping the prover deterministic.
//!
//! **Instance encoding:** `Encoding` is implemented for `SigmaIA<S>` by forwarding to
//! `SigmaProtocol::instance_label()`.

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

    fn protocol_id(&self) -> impl AsRef<[u8]> {
        // The full 64-byte sigma-proofs identifier. For `ComposedRelation` this
        // is computed at runtime from the composition tree; for canonical
        // sigma protocols it is a static ASCII label zero-padded to 64 bytes.
        // DSFS passes this with `SpongeInfo` and encoded session into `DomainSeparator::derive`.
        self.0.protocol_identifier()
    }

    fn prove<P: ProverChannel>(&self, ch: &mut P, instance: &SigmaIA<S>, witness: &(S::Witness, [u8; 32])) {
        let (w, seed) = witness;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(*seed);

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

    fn verify<V: VerifierChannel>(&self, ch: &mut V, instance: &SigmaIA<S>) -> VerificationResult<()> {
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
