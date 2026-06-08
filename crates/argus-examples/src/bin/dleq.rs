//! Chaum-Pedersen DLEQ over a preprocessed public key.
//!
//! Proves that two pairs share the same discrete log:
//!   given (g, h, u, v),  prove knowledge of x  such that  h = g^x  AND  v = u^x.
//!
//! This is the canonical place preprocessing earns its keep. The pair
//! (g, h = g^x) is a long-term public key, generated once by a KeyGen
//! ceremony. Every subsequent DLEQ proof binds back to that same (g, h),
//! so the verifier needs (g, h) up front — exactly the preprocessing
//! pattern. Lots of production primitives are built on top of this
//! shape: VRFs (Goldberg/Papadopoulos), OPRFs (Hashed-Diffie-Hellman),
//! ElGamal decryption-correctness proofs, threshold decryption mixnets,
//! verifiable secret sharing, Privacy Pass, …
//!
//! Protocol (parallel Schnorr in two generators g and u):
//!   Prover sends commitments  K1 = g^k,  K2 = u^k     (k random)
//!   Verifier sends challenge  c
//!   Prover sends response     r = k + c * x
//!   Verify: g^r == K1 * h^c   AND   u^r == K2 * v^c
//!
//! Mapping onto the indexed-relation surface:
//!
//!   Index       = (g, h)       — long-term public key, the preprocessing
//!                                 input. ProverKey and VerifierKey both
//!                                 hold this pair; VK commits to it via
//!                                 `CommittedIndex`.
//!   ProverKey   = DleqKey { g, h }
//!   VerifierKey = DleqKey { g, h }
//!   Instance    = (u, v)       — per-claim DLEQ challenge pair
//!   Witness     = x            — the long-term secret discrete log
//!
//! The committed verifier key is absorbed BEFORE the first challenge, so
//! a proof produced under (g, h_alice) cannot be re-targeted at
//! (g, h_bob) — the transcripts diverge from the very first squeeze.
//!
//! In the examples ladder, this is the first preprocessing example: the
//! compiled wrapper stores no keys, and the derived keys are passed as inputs
//! to prove and verify.
//!
//! Run:  cargo run -p argus-examples --bin dleq

use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::PrimeField;
use ark_std::UniformRand;
use rand::rngs::OsRng;
use spongefish_dsfs as dsfs;

use ia_core::prelude::*;
use ia_core::{
    CommittedIndex, CommittedIndexBytes, Decoding, Deserialize, Encoding, Indexer, ProverChannel,
    VerificationError, VerificationResult, VerifierChannel,
};

// ---------------------------------------------------------------------------
// Preprocessing key + its canonical commitment
// ---------------------------------------------------------------------------

/// The DLEQ preprocessing key — the long-term (g, h) pair. Held by both
/// prover and verifier; the verifier-side copy is what `CommittedIndex`
/// hashes into transcript bytes.
#[derive(Clone, Debug)]
struct DleqKey<G: CurveGroup> {
    g: G,
    h: G,
}

impl<G: CurveGroup + Encoding> CommittedIndex for DleqKey<G> {
    fn committed_index(&self) -> CommittedIndexBytes {
        // Tag + (g || h). Tag namespaces the bytes so this commitment can
        // never be confused with some other verifier-key encoding.
        let mut out = Vec::new();
        out.extend_from_slice(b"dleq:vk:v1");
        out.extend_from_slice(self.g.encode().as_ref());
        out.extend_from_slice(self.h.encode().as_ref());
        CommittedIndexBytes::new(out)
    }
}

// ---------------------------------------------------------------------------
// The body — implements the indexed author trait
// ---------------------------------------------------------------------------

fn dleq_protocol_id() -> [u8; 32] {
    ia_core::pad_protocol_id(b"dleq-chaum-pedersen")
}

struct DleqIndexer<G: CurveGroup>(core::marker::PhantomData<G>);

struct DleqProver<G: CurveGroup>(core::marker::PhantomData<G>);

struct DleqVerifier<G: CurveGroup>(core::marker::PhantomData<G>);

impl<G: CurveGroup> Default for DleqIndexer<G> {
    fn default() -> Self {
        Self(core::marker::PhantomData)
    }
}

ia_core::impl_preprocessing_argument! {
    indexer impl<G> for DleqIndexer<G>
    where
        G: CurveGroup + Encoding,
    {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            dleq_protocol_id()
        }

        /// (u, v) — the per-claim DLEQ pair
        type Instance = (G, G);
        /// (g, h)
        type Index = (G, G);
        type ProverKey = DleqKey<G>;
        type VerifierKey = DleqKey<G>;

        /// Deterministic indexer: both keys are the same (g, h) pair. The
        /// verifier-side key exposes a canonical commitment via
        /// `CommittedIndex`; the prover-side key is the same data but
        /// without the trait obligation.
        fn preprocess(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
            let key = DleqKey { g: ix.0, h: ix.1 };
            (key.clone(), key)
        }
    }
}

impl<G: CurveGroup> Default for DleqProver<G> {
    fn default() -> Self {
        Self(core::marker::PhantomData)
    }
}

ia_core::impl_preprocessing_argument! {
    prover impl<G> for DleqProver<G>
    where
        G: CurveGroup + PrimeGroup + Encoding + Deserialize,
        G::ScalarField: PrimeField + Encoding + Decoding + Deserialize,
    {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            dleq_protocol_id()
        }

        /// (u, v) — the per-claim DLEQ pair
        type Instance = (G, G);
        /// x
        type Witness = G::ScalarField;
        type ProverKey = DleqKey<G>;

        #[allow(non_snake_case)]
        fn prove<P: ProverChannel<Unit = u8>>(
            &self,
            ch: &mut P,
            pk: &DleqKey<G>,
            instance: &(G, G),
            witness: &G::ScalarField,
        ) {
            let DleqKey { g, h: _ } = *pk;
            let (u, _v) = *instance;
            let x = *witness;

            let k = G::ScalarField::rand(&mut OsRng);
            let K1 = g * k;
            let K2 = u * k;
            ch.send_prover_message(&K1);
            ch.send_prover_message(&K2);

            let c: G::ScalarField = ch.read_verifier_message();
            let r = k + c * x;
            ch.send_prover_message(&r);
        }
    }
}

impl<G: CurveGroup> Default for DleqVerifier<G> {
    fn default() -> Self {
        Self(core::marker::PhantomData)
    }
}

ia_core::impl_preprocessing_argument! {
    verifier impl<G> for DleqVerifier<G>
    where
        G: CurveGroup + PrimeGroup + Encoding + Deserialize,
        G::ScalarField: PrimeField + Encoding + Decoding + Deserialize,
    {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            dleq_protocol_id()
        }

        /// (u, v) — the per-claim DLEQ pair
        type Instance = (G, G);
        type VerifierKey = DleqKey<G>;

        #[allow(non_snake_case)]
        fn verify<V: VerifierChannel<Unit = u8>>(
            &self,
            ch: &mut V,
            vk: &DleqKey<G>,
            instance: &(G, G),
        ) -> VerificationResult<()> {
            let DleqKey { g, h } = *vk;
            let (u, v) = *instance;

            let K1: G = ch.read_prover_message()?;
            let K2: G = ch.read_prover_message()?;
            let c: G::ScalarField = ch.send_verifier_message();
            let r: G::ScalarField = ch.read_prover_message()?;

            if g * r == K1 + h * c && u * r == K2 + v * c {
                Ok(())
            } else {
                Err(VerificationError)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Main: KeyGen once, prove many DLEQ pairs
// ---------------------------------------------------------------------------

fn main() {
    type G = ark_curve25519::EdwardsProjective;
    type F = ark_curve25519::Fr;

    println!("=== Chaum-Pedersen DLEQ (preprocessed public key) ===\n");
    let session = spongefish::session!("dleq example");

    // -------- one-time KeyGen ----------------------------------------------
    let g = G::generator();
    let x = F::rand(&mut OsRng); // long-term secret
    let h = g * x; // public key

    // -------- preprocessing step -------------------------------------------
    // The indexer derives both keys once. The prover and verifier roles are
    // compiled independently and receive only their own key.
    let indexer = DleqIndexer::<G>::default();
    let prover = dsfs::preprocessing_non_interactive_argument_prover(
        DleqProver::<G>::default(),
        dsfs::Keccak::default(),
    );
    let verifier = dsfs::preprocessing_non_interactive_argument_verifier(
        DleqVerifier::<G>::default(),
        dsfs::Keccak::default(),
    );
    let (proving_key, verifier_key) = indexer
        .preprocess_checked(&(g, h))
        .expect("matching committed indices");

    // -------- inspect the preprocessed key directly ------------------------
    println!("Preprocessed public key:");
    println!(
        "  committed_index: 0x{}",
        hex::encode(proving_key.committed_index().as_bytes())
    );
    println!("  verifier_key:    {verifier_key:?}");
    println!();

    // -------- many proofs under one preprocessed key -----------------------
    // Each "claim" is a different DLEQ pair (u, v = u^x). In real use the
    // (u, v) typically comes from a per-session VRF / OPRF blinding step.
    // Here we just sample u uniformly and compute v = u^x.
    for i in 0..3 {
        let u = G::generator() * F::rand(&mut OsRng);
        let v = u * x;
        let instance = (u, v);
        let proof = prover.prove(&proving_key, &session, &instance, &x);
        verifier
            .verify(&verifier_key, &session, &instance, &proof)
            .expect("verify");
        println!(
            "Claim {i}: verified DLEQ pair (u, u^x) under preprocessed key ({} proof bytes)",
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
    use ia_core::{
        PreprocessingNonInteractiveArgumentProver, PreprocessingNonInteractiveArgumentVerifier,
    };

    type G = ark_curve25519::EdwardsProjective;
    type F = ark_curve25519::Fr;

    fn assert_preprocessed_prover<N: PreprocessingNonInteractiveArgumentProver>(_: &N) {}

    fn assert_preprocessed_verifier<N: PreprocessingNonInteractiveArgumentVerifier>(_: &N) {}

    fn keygen() -> (G, F, G) {
        let g = G::generator();
        let x = F::rand(&mut OsRng);
        let h = g * x;
        (g, x, h)
    }

    #[test]
    fn dleq_roundtrip() {
        let session = spongefish::session!("dleq test");
        let (g, x, h) = keygen();
        let indexer = DleqIndexer::<G>::default();
        let prover = dsfs::preprocessing_non_interactive_argument_prover::<_, [u8; 64], _>(
            DleqProver::<G>::default(),
            dsfs::Keccak::default(),
        );
        let verifier = dsfs::preprocessing_non_interactive_argument_verifier::<_, [u8; 64], _>(
            DleqVerifier::<G>::default(),
            dsfs::Keccak::default(),
        );
        let (pk, vk) = indexer
            .preprocess_checked(&(g, h))
            .expect("matching committed indices");

        let u = G::generator() * F::rand(&mut OsRng);
        let v = u * x;
        let proof = prover.prove(&pk, &session, &(u, v), &x);
        verifier
            .verify(&vk, &session, &(u, v), &proof)
            .expect("verify under correct key");
    }

    #[test]
    fn dleq_via_separate_prover_and_verifier_roles() {
        let session = spongefish::session!("dleq role split test");
        let (g, x, h) = keygen();
        let indexer = DleqIndexer::<G>::default();
        let (pk, vk) = indexer
            .preprocess_checked(&(g, h))
            .expect("matching committed indices");

        let prover_nia = dsfs::preprocessing_non_interactive_argument_prover(
            DleqProver::<G>::default(),
            dsfs::Keccak::default(),
        );
        let verifier_nia = dsfs::preprocessing_non_interactive_argument_verifier(
            DleqVerifier::<G>::default(),
            dsfs::Keccak::default(),
        );

        assert_preprocessed_prover(&prover_nia);
        assert_preprocessed_verifier(&verifier_nia);

        let u = G::generator() * F::rand(&mut OsRng);
        let v = u * x;
        // Keys are passed explicitly on each call; capability separation comes from
        // the prover-only / verifier-only compiled objects, not a key-binding wrapper.
        let proof = prover_nia.prove(&pk, &session, &(u, v), &x);
        assert!(!proof.is_empty());

        verifier_nia
            .verify(&vk, &session, &(u, v), &proof)
            .expect("separate DLEQ verifier accepts prover proof");
    }

    /// A proof produced under (g, h_alice) cannot be redirected at
    /// (g, h_bob) — even if (u, v) is consistent under Alice's x. The
    /// committed_index absorption catches it (transcripts diverge).
    #[test]
    fn dleq_proof_does_not_cross_keys() {
        let session = spongefish::session!("dleq test");
        let (g, x_alice, h_alice) = keygen();
        let (_, _x_bob, h_bob) = keygen();

        let indexer = DleqIndexer::<G>::default();
        let prover = dsfs::preprocessing_non_interactive_argument_prover(
            DleqProver::<G>::default(),
            dsfs::Keccak::default(),
        );
        let verifier = dsfs::preprocessing_non_interactive_argument_verifier(
            DleqVerifier::<G>::default(),
            dsfs::Keccak::default(),
        );
        let (pk_alice, _vk_alice) = indexer
            .preprocess_checked(&(g, h_alice))
            .expect("matching committed indices");
        let (_pk_bob, vk_bob) = indexer
            .preprocess_checked(&(g, h_bob))
            .expect("matching committed indices");
        assert_ne!(pk_alice.committed_index(), vk_bob.committed_index());

        // Alice produces a valid DLEQ for (u, u^x_alice).
        let u = G::generator() * F::rand(&mut OsRng);
        let v_alice = u * x_alice;
        let proof = prover.prove(&pk_alice, &session, &(u, v_alice), &x_alice);

        // Verifying under Bob's key rejects — the bound public key differs.
        assert!(
            verifier
                .verify(&vk_bob, &session, &(u, v_alice), &proof)
                .is_err()
        );
    }

    /// Mismatching (u, v) — i.e., v != u^x — must be rejected by the
    /// honest verifier under the correct key. This exercises the
    /// algebraic check (the second equation u^r == K2 + v*c fails).
    #[test]
    fn dleq_rejects_inconsistent_pair() {
        let session = spongefish::session!("dleq test");
        let (g, x, h) = keygen();
        let indexer = DleqIndexer::<G>::default();
        let prover = dsfs::preprocessing_non_interactive_argument_prover(
            DleqProver::<G>::default(),
            dsfs::Keccak::default(),
        );
        let verifier = dsfs::preprocessing_non_interactive_argument_verifier(
            DleqVerifier::<G>::default(),
            dsfs::Keccak::default(),
        );
        let (pk, vk) = indexer
            .preprocess_checked(&(g, h))
            .expect("matching committed indices");

        let u = G::generator() * F::rand(&mut OsRng);
        let v_wrong = u * F::rand(&mut OsRng); // not u^x
        let proof = prover.prove(&pk, &session, &(u, v_wrong), &x);
        assert!(
            verifier
                .verify(&vk, &session, &(u, v_wrong), &proof)
                .is_err()
        );
    }

    /// The proving key carries the tagged committed index derived from the
    /// verifier key at `preprocess` time.
    #[test]
    fn dleq_proving_key_carries_tagged_committed_index() {
        let (g, _x, h) = keygen();
        let (pk, _vk) = DleqIndexer::<G>::default()
            .preprocess_checked(&(g, h))
            .expect("matching committed indices");
        assert!(pk.committed_index().as_bytes().starts_with(b"dleq:vk:v1"));
    }
}
