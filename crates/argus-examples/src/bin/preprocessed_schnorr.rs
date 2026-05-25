//! Preprocessed Schnorr — same protocol math as `schnorr.rs`, lifted into
//! the indexed (preprocessed) author trait.
//!
//! The cryptographic content is identical to plain Schnorr (knowledge of x
//! such that pk = x * G, with the standard three-message sigma protocol).
//! The difference is purely structural: the generator G is *preprocessed*
//! instead of riding inside every per-claim instance.
//!
//! Layer-by-layer, here is where each piece lives. This is the picture that
//! tripped up the recent design discussion, so the comments are dense on
//! purpose.
//!
//! ┌──────────────────── 1. Author trait ───────────────────────────────┐
//! │  IndexedInteractiveArgument *declares*:                            │
//! │    type Index       = G        (static problem description)        │
//! │    type ProverKey   = G        (what the prover holds after index) │
//! │    type VerifierKey = `SchnorrVerifierKey<G>` (verifier-side key)  │
//! │    type Instance    = G        (per-claim public key pk = x*G)     │
//! │    type Witness     = scalar x                                     │
//! │    fn index(&Index) -> (ProverKey, VerifierKey)                    │
//! │  The body knows *how to derive* keys from an index but doesn't     │
//! │  hold any values.                                                  │
//! └────────────────────────────────────────────────────────────────────┘
//! ┌──────────────────── 2. Wrapper struct ─────────────────────────────┐
//! │  non_interactive_argument(body, sponge).prepare(&g)                │
//! │  -> PreparedDsfsArgument { ia, pk, vk, committed_index, sponge }   │
//! │  This is the wrapper that *holds* generated keys as private fields.│
//! └────────────────────────────────────────────────────────────────────┘
//! ┌──────────────────── 3. Capability trait (`Preprocessed`) ──────────┐
//! │  PreparedDsfsArgument implements `Preprocessed`, which is the      │
//! │  discoverable home for the three accessors:                        │
//! │    fn prover_key()      -> &Self::ProverKey                        │
//! │    fn verifier_key()    -> &Self::VerifierKey                      │
//! │    fn committed_index() -> &CommittedIndexBytes                    │
//! │  Same trait, same accessor names whether you're holding a          │
//! │  PreparedArgument (IA layer) or a PreparedDsfsArgument (NARG).     │
//! └────────────────────────────────────────────────────────────────────┘
//!
//! Run:  cargo run -p argus-examples --bin preprocessed_schnorr

use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::PrimeField;
use ark_std::UniformRand;
use rand::rngs::OsRng;
use spongefish_dsfs as dsfs;

use ia_core::{
    ArgumentBody, CommittedIndexBytes, Decoding, Deserialize, Encoding, IndexedBody,
    IndexedInteractiveArgument, NonInteractiveArgument, Preprocessed, ProtocolBody, ProverChannel,
    VerificationError, VerificationResult, VerifierChannel, VerifierKeyCommitment,
};

// ---------------------------------------------------------------------------
// Verifier key + its canonical commitment
// ---------------------------------------------------------------------------

/// Verifier key — wraps the generator G so we have a place to implement
/// `VerifierKeyCommitment`. The prepared transcript absorbs whatever
/// `committed_index()` returns before the first challenge, so this is what
/// binds every proof to *this* specific generator.
#[derive(Clone, Debug)]
struct SchnorrVerifierKey<G: CurveGroup>(G);

impl<G: CurveGroup + Encoding> VerifierKeyCommitment for SchnorrVerifierKey<G> {
    fn committed_index(&self) -> CommittedIndexBytes {
        // Tag the bytes so this commitment cannot be confused with any other
        // verifier-key encoding in the system.
        let mut out = Vec::new();
        out.extend_from_slice(b"preprocessed-schnorr:vk:v1");
        out.extend_from_slice(self.0.encode().as_ref());
        CommittedIndexBytes::new(out)
    }
}

// ---------------------------------------------------------------------------
// The body — implements the indexed author trait
// ---------------------------------------------------------------------------

struct PreprocessedSchnorr<G: CurveGroup>(core::marker::PhantomData<G>);

impl<G: CurveGroup> Default for PreprocessedSchnorr<G> {
    fn default() -> Self {
        Self(core::marker::PhantomData)
    }
}

impl<G> ProtocolBody for PreprocessedSchnorr<G>
where
    G: CurveGroup + PrimeGroup + Encoding + Deserialize,
    G::ScalarField: PrimeField + Encoding + Decoding + Deserialize,
{
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        ia_core::pad_protocol_id(b"preprocessed-schnorr")
    }
}

impl<G> ArgumentBody for PreprocessedSchnorr<G>
where
    G: CurveGroup + PrimeGroup + Encoding + Deserialize,
    G::ScalarField: PrimeField + Encoding + Decoding + Deserialize,
{
    type Instance = G;
    type Witness = G::ScalarField;
}

impl<G> IndexedBody for PreprocessedSchnorr<G>
where
    G: CurveGroup + PrimeGroup + Encoding + Deserialize,
    G::ScalarField: PrimeField + Encoding + Decoding + Deserialize,
{
    type Index = G;
    type ProverKey = G;
    type VerifierKey = SchnorrVerifierKey<G>;

    /// Deterministic indexer. Both prover and verifier end up holding G,
    /// but the verifier wraps it in `SchnorrVerifierKey` so a canonical
    /// commitment can be derived for the transcript.
    fn index(&self, ix: &G) -> (G, SchnorrVerifierKey<G>) {
        (*ix, SchnorrVerifierKey(*ix))
    }
}

impl<G> IndexedInteractiveArgument for PreprocessedSchnorr<G>
where
    G: CurveGroup + PrimeGroup + Encoding + Deserialize,
    G::ScalarField: PrimeField + Encoding + Decoding + Deserialize,
{
    #[allow(non_snake_case)]
    fn prove<P: ProverChannel>(&self, ch: &mut P, pk: &G, _instance: &G, witness: &G::ScalarField) {
        let G_gen = *pk;
        let k = G::ScalarField::rand(&mut OsRng);
        let K = G_gen * k;
        ch.send_prover_message(&K);
        let c: G::ScalarField = ch.read_verifier_message();
        let r = k + c * witness;
        ch.send_prover_message(&r);
    }

    #[allow(non_snake_case)]
    fn verify<V: VerifierChannel>(
        &self,
        ch: &mut V,
        vk: &SchnorrVerifierKey<G>,
        instance: &G,
    ) -> VerificationResult<()> {
        let G_gen = vk.0;
        let X = *instance;
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
// Main: preprocess once, prove many
// ---------------------------------------------------------------------------

fn main() {
    type G = ark_curve25519::EdwardsProjective;
    type F = ark_curve25519::Fr;

    println!("=== Preprocessed Schnorr ===\n");
    let session = spongefish::session!("preprocessed schnorr example");

    // 1. Preprocessing step. `non_interactive_argument(body, sponge)` wraps the body;
    //    `.prepare(&generator)` calls `body.index(&generator)` and stashes
    //    `(pk, vk, committed_index)` inside the returned `PreparedDsfsArgument`.
    let generator = G::generator();
    let prepared = dsfs::non_interactive_argument(
        PreprocessedSchnorr::<G>::default(),
        dsfs::Keccak::default(),
    )
    .prepare(&generator);

    // 2. Inspect preprocessing keys through the `Preprocessed` capability.
    //    The trait is the single discoverable home for these accessors;
    //    PreparedArgument (IA layer) and PreparedDsfsArgument (NARG layer) both
    //    implement it identically, so a generic function bounded by
    //    `P: Preprocessed` works on either.
    //
    //    The inherent shortcuts on the wrapper struct
    //    (e.g. `prepared.verifier_key()`) forward to the same fields and
    //    are kept for ergonomics — callers holding a concrete type don't
    //    need to import the trait to read a field.
    fn audit<P: Preprocessed>(label: &str, p: &P)
    where
        P::VerifierKey: core::fmt::Debug,
        P::ProverKey: core::fmt::Debug,
    {
        println!("{label}:");
        println!(
            "  committed_index: 0x{}",
            hex::encode(p.committed_index().as_bytes())
        );
        println!("  verifier_key:    {:?}", p.verifier_key());
        // prover_key() returns secret material in production protocols;
        // here pk == vk == generator, so it's harmless to print.
        println!("  prover_key:      {:?}\n", p.prover_key());
    }
    audit(
        "Preprocessed inspection (via the `Preprocessed` trait)",
        &prepared,
    );

    // 3. Many claims, one preprocessed setup. Per-claim instance is just
    //    the public key — the generator no longer rides along.
    for i in 0..3 {
        let sk = F::rand(&mut OsRng);
        let pk = generator * sk;
        let proof = prepared.prove(&session, &pk, &sk);
        prepared
            .verify(&session, &pk, &proof)
            .expect("verify failed");
        println!(
            "Claim {i}: pk = {pk:?} -> verified ({} proof bytes)",
            proof.as_bytes().len(),
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    type G = ark_curve25519::EdwardsProjective;
    type F = ark_curve25519::Fr;

    #[test]
    fn preprocessed_schnorr_roundtrip() {
        let session = spongefish::session!("preprocessed schnorr test");
        let g = G::generator();
        let prepared = dsfs::non_interactive_argument(
            PreprocessedSchnorr::<G>::default(),
            dsfs::Keccak::default(),
        )
        .prepare(&g);

        let sk = F::rand(&mut OsRng);
        let pk = g * sk;
        let proof = prepared.prove(&session, &pk, &sk);
        prepared
            .verify(&session, &pk, &proof)
            .expect("verification under correct generator");
    }

    /// Two prepared instances built with different generators must not
    /// accept each other's proofs. The transcript divergence comes from
    /// the differing `committed_index()` absorption — not from any explicit
    /// check in the protocol code.
    #[test]
    fn preprocessed_schnorr_verify_rejects_under_different_generator() {
        let session = spongefish::session!("preprocessed schnorr test");
        let g1 = G::generator();
        let g2 = g1 + G::generator(); // 2 * generator — distinct from g1

        let prepared_g1 = dsfs::non_interactive_argument(
            PreprocessedSchnorr::<G>::default(),
            dsfs::Keccak::default(),
        )
        .prepare(&g1);
        let prepared_g2 = dsfs::non_interactive_argument(
            PreprocessedSchnorr::<G>::default(),
            dsfs::Keccak::default(),
        )
        .prepare(&g2);

        // Sanity: different generators produce different committed indices.
        assert_ne!(prepared_g1.committed_index(), prepared_g2.committed_index(),);

        let sk = F::rand(&mut OsRng);
        let pk_under_g1 = g1 * sk;
        let proof = prepared_g1.prove(&session, &pk_under_g1, &sk);

        // Same instance bytes; different prepared verifier => rejects.
        assert!(prepared_g2.verify(&session, &pk_under_g1, &proof).is_err());
    }

    /// Generic-consumer test: a `fn audit<P: Preprocessed>(...)` can pull
    /// preprocessing keys off any prepared wrapper, regardless of plane.
    /// This is the polymorphism win that justifies the `Preprocessed`
    /// capability trait.
    #[test]
    fn preprocessed_capability_reaches_keys_generically() {
        fn audit<P: Preprocessed>(p: &P) -> Vec<u8> {
            p.committed_index().as_bytes().to_vec()
        }
        let g = G::generator();
        // Session type pinned to [u8; 64] (`spongefish::session!` returns that).
        // Other tests in this file pin it implicitly by calling `prepare(...).prove(&session, ...)`.
        let prepared = dsfs::non_interactive_argument::<_, [u8; 64], _>(
            PreprocessedSchnorr::<G>::default(),
            dsfs::Keccak::default(),
        )
        .prepare(&g);
        let bytes = audit(&prepared);
        assert!(bytes.starts_with(b"preprocessed-schnorr:vk:v1"));
    }
}
