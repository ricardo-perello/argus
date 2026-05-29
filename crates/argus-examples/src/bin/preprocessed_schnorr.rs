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
//! │  PreprocessingInteractiveArgument *declares*:                            │
//! │    type Index       = G        (static problem description)        │
//! │    type ProverKey   = G        (what the prover holds after index) │
//! │    type VerifierKey = `SchnorrVerifierKey<G>` (verifier-side key)  │
//! │    type Instance    = G        (per-claim public key pk = x*G)     │
//! │    type Witness     = scalar x                                     │
//! │    fn index(&Index) -> (ProverKey, VerifierKey)                    │
//! │  The body knows *how to derive* keys from an index but doesn't     │
//! │  hold any values.                                                  │
//! └────────────────────────────────────────────────────────────────────┘
//! ┌──────────────────── 2. Compiled wrapper (stateless) ───────────────┐
//! │  preprocessing_non_interactive_argument(body, sponge)              │
//! │  -> PreprocessedDsfsArgument { ia, sponge }   (holds NO keys)      │
//! └────────────────────────────────────────────────────────────────────┘
//! ┌──────────────────── 3. Indexer + keys-as-inputs ───────────────────┐
//! │  pnia.preprocess(&g) -> (ProvingKey { key, committed_index }, vk)  │
//! │  pnia.prove(&proving_key, session, x, w) / pnia.verify(&vk, ...)   │
//! │  Keys are inputs; the verifier holds only vk, the prover only the  │
//! │  proving key (which carries the committed index).                  │
//! └────────────────────────────────────────────────────────────────────┘
//!
//! Run:  cargo run -p argus-examples --bin preprocessed_schnorr

use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::PrimeField;
use ark_std::UniformRand;
use rand::rngs::OsRng;
use spongefish_dsfs as dsfs;

use ia_core::{
    CommittedIndexBytes, Decoding, Deserialize, Encoding, PreprocessingNonInteractiveArgument,
    ProverChannel, VerificationError, VerificationResult, VerifierChannel, VerifierKeyCommitment,
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

ia_core::impl_preprocessing_argument! {
    impl<G> PreprocessingInteractiveArgument for PreprocessedSchnorr<G>
    where
        G: CurveGroup + PrimeGroup + Encoding + Deserialize,
        G::ScalarField: PrimeField + Encoding + Decoding + Deserialize,
    {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            ia_core::pad_protocol_id(b"preprocessed-schnorr")
        }

        type Instance = G;
        type Witness = G::ScalarField;
        type Index = G;
        type ProverKey = G;
        type VerifierKey = SchnorrVerifierKey<G>;

        /// Deterministic indexer. Both prover and verifier end up holding G,
        /// but the verifier wraps it in `SchnorrVerifierKey` so a canonical
        /// commitment can be derived for the transcript.
        fn index(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
            (*ix, SchnorrVerifierKey(*ix))
        }

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
}

// ---------------------------------------------------------------------------
// Main: preprocess once, prove many
// ---------------------------------------------------------------------------

fn main() {
    type G = ark_curve25519::EdwardsProjective;
    type F = ark_curve25519::Fr;

    println!("=== Preprocessed Schnorr ===\n");
    let session = spongefish::session!("preprocessed schnorr example");

    // 1. Compile the stateless wrapper, then run the indexer.
    //    `preprocessing_non_interactive_argument(body, sponge)` holds no keys;
    //    `.preprocess(&generator)` calls `body.index(&generator)`, bakes
    //    `vk.committed_index()` into the proving key, and returns
    //    `(ProvingKey { key, committed_index }, verifier_key)`.
    let generator = G::generator();
    let pnia = dsfs::preprocessing_non_interactive_argument(
        PreprocessedSchnorr::<G>::default(),
        dsfs::Keccak::default(),
    );
    let (proving_key, verifier_key) = pnia.preprocess(&generator);

    // 2. Inspect the asymmetry directly from the keys — no capability trait
    //    needed, since `preprocess` hands you the keys as values.
    println!("Preprocessed inspection:");
    println!(
        "  committed_index: 0x{}",
        hex::encode(proving_key.committed_index.as_bytes())
    );
    println!("  verifier_key:    {:?}", verifier_key);
    // prover_key is secret material in production protocols; here pk == vk ==
    // generator, so it's harmless to print.
    println!("  prover_key:      {:?}\n", proving_key.key);

    // 3. Many claims, one preprocessed setup. Per-claim instance is just the
    //    public key — the generator no longer rides along. The prover passes
    //    the proving key, the verifier passes the verifier key.
    for i in 0..3 {
        let sk = F::rand(&mut OsRng);
        let pk = generator * sk;
        let proof = pnia.prove(&proving_key, &session, &pk, &sk);
        pnia.verify(&verifier_key, &session, &pk, &proof)
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
        let pnia = dsfs::preprocessing_non_interactive_argument(
            PreprocessedSchnorr::<G>::default(),
            dsfs::Keccak::default(),
        );
        let (proving_key, verifier_key) = pnia.preprocess(&g);

        let sk = F::rand(&mut OsRng);
        let pk = g * sk;
        let proof = pnia.prove(&proving_key, &session, &pk, &sk);
        pnia.verify(&verifier_key, &session, &pk, &proof)
            .expect("verification under correct generator");
    }

    /// Two indexings with different generators must not accept each other's
    /// proofs. The transcript divergence comes from the differing
    /// `committed_index` absorption — not from any explicit check in the
    /// protocol code.
    #[test]
    fn preprocessed_schnorr_verify_rejects_under_different_generator() {
        let session = spongefish::session!("preprocessed schnorr test");
        let g1 = G::generator();
        let g2 = g1 + G::generator(); // 2 * generator — distinct from g1

        let pnia = dsfs::preprocessing_non_interactive_argument(
            PreprocessedSchnorr::<G>::default(),
            dsfs::Keccak::default(),
        );
        let (pk_g1, _vk_g1) = pnia.preprocess(&g1);
        let (_pk_g2, vk_g2) = pnia.preprocess(&g2);

        // Sanity: different generators produce different committed indices.
        assert_ne!(pk_g1.committed_index, vk_g2.committed_index());

        let sk = F::rand(&mut OsRng);
        let pk_under_g1 = g1 * sk;
        let proof = pnia.prove(&pk_g1, &session, &pk_under_g1, &sk);

        // Same instance bytes; verifier key from a different generator => rejects.
        assert!(pnia
            .verify(&vk_g2, &session, &pk_under_g1, &proof)
            .is_err());
    }

    /// The proving key carries the tagged committed index derived from the
    /// verifier key at `preprocess` time.
    #[test]
    fn preprocessed_proving_key_carries_tagged_committed_index() {
        let g = G::generator();
        let pnia = dsfs::preprocessing_non_interactive_argument::<_, [u8; 64], _>(
            PreprocessedSchnorr::<G>::default(),
            dsfs::Keccak::default(),
        );
        let (proving_key, _vk) = pnia.preprocess(&g);
        assert!(proving_key
            .committed_index
            .as_bytes()
            .starts_with(b"preprocessed-schnorr:vk:v1"));
    }
}
