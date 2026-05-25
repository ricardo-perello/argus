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
//!                                 `VerifierKeyCommitment`.
//!   ProverKey   = DleqKey { g, h }
//!   VerifierKey = DleqKey { g, h }
//!   Instance    = (u, v)       — per-claim DLEQ challenge pair
//!   Witness     = x            — the long-term secret discrete log
//!
//! The committed verifier key is absorbed BEFORE the first challenge, so
//! a proof produced under (g, h_alice) cannot be re-targeted at
//! (g, h_bob) — the transcripts diverge from the very first squeeze.
//!
//! See preprocessed_schnorr.rs for the same "where do the keys live"
//! diagram. This file mirrors that structure; the only thing new is the
//! protocol math.
//!
//! Run:  cargo run -p argus-examples --bin dleq

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
// Preprocessing key + its canonical commitment
// ---------------------------------------------------------------------------

/// The DLEQ preprocessing key — the long-term (g, h) pair. Held by both
/// prover and verifier; the verifier-side copy is what `VerifierKeyCommitment`
/// hashes into transcript bytes.
#[derive(Clone, Debug)]
struct DleqKey<G: CurveGroup> {
    g: G,
    h: G,
}

impl<G: CurveGroup + Encoding> VerifierKeyCommitment for DleqKey<G> {
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

struct Dleq<G: CurveGroup>(core::marker::PhantomData<G>);

impl<G: CurveGroup> Default for Dleq<G> {
    fn default() -> Self {
        Self(core::marker::PhantomData)
    }
}

impl<G> ProtocolBody for Dleq<G>
where
    G: CurveGroup + PrimeGroup + Encoding + Deserialize,
    G::ScalarField: PrimeField + Encoding + Decoding + Deserialize,
{
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        ia_core::pad_protocol_id(b"dleq-chaum-pedersen")
    }
}

impl<G> ArgumentBody for Dleq<G>
where
    G: CurveGroup + PrimeGroup + Encoding + Deserialize,
    G::ScalarField: PrimeField + Encoding + Decoding + Deserialize,
{
    type Instance = (G, G); // (u, v) — the per-claim DLEQ pair
    type Witness = G::ScalarField; // x
}

impl<G> IndexedBody for Dleq<G>
where
    G: CurveGroup + PrimeGroup + Encoding + Deserialize,
    G::ScalarField: PrimeField + Encoding + Decoding + Deserialize,
{
    type Index = (G, G); // (g, h)
    type ProverKey = DleqKey<G>;
    type VerifierKey = DleqKey<G>;

    /// Deterministic indexer: both keys are the same (g, h) pair. The
    /// verifier-side key exposes a canonical commitment via
    /// `VerifierKeyCommitment`; the prover-side key is the same data but
    /// without the trait obligation.
    fn index(&self, ix: &(G, G)) -> (DleqKey<G>, DleqKey<G>) {
        let key = DleqKey { g: ix.0, h: ix.1 };
        (key.clone(), key)
    }
}

impl<G> IndexedInteractiveArgument for Dleq<G>
where
    G: CurveGroup + PrimeGroup + Encoding + Deserialize,
    G::ScalarField: PrimeField + Encoding + Decoding + Deserialize,
{
    #[allow(non_snake_case)]
    fn prove<P: ProverChannel>(
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

    #[allow(non_snake_case)]
    fn verify<V: VerifierChannel>(
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
    // non_interactive_argument(body, sponge).prepare(&(g, h)) calls body.index(&(g, h))
    // once and stashes (pk, vk, committed_index) inside the returned
    // PreparedDsfsArgument. Every subsequent prove/verify call reads from those.
    let prepared = dsfs::non_interactive_argument(Dleq::<G>::default(), dsfs::Keccak::default())
        .prepare(&(g, h));

    // -------- inspect preprocessing via the Preprocessed capability --------
    // Bound by `P: Preprocessed`, so the same helper works on any prepared
    // wrapper — PreparedArgument (IA layer) or PreparedDsfsArgument (NARG layer).
    fn audit<P: Preprocessed>(label: &str, p: &P)
    where
        P::VerifierKey: core::fmt::Debug,
    {
        println!("{label}:");
        println!(
            "  committed_index: 0x{}",
            hex::encode(p.committed_index().as_bytes())
        );
        println!("  verifier_key:    {:?}", p.verifier_key());
    }
    audit(
        "Preprocessed public key (via `Preprocessed` trait)",
        &prepared,
    );
    println!();

    // -------- many proofs under one preprocessed key -----------------------
    // Each "claim" is a different DLEQ pair (u, v = u^x). In real use the
    // (u, v) typically comes from a per-session VRF / OPRF blinding step.
    // Here we just sample u uniformly and compute v = u^x.
    for i in 0..3 {
        let u = G::generator() * F::rand(&mut OsRng);
        let v = u * x;
        let instance = (u, v);
        let proof = prepared.prove(&session, &instance, &x);
        prepared
            .verify(&session, &instance, &proof)
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

    type G = ark_curve25519::EdwardsProjective;
    type F = ark_curve25519::Fr;

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
        let prepared =
            dsfs::non_interactive_argument(Dleq::<G>::default(), dsfs::Keccak::default())
                .prepare(&(g, h));

        let u = G::generator() * F::rand(&mut OsRng);
        let v = u * x;
        let proof = prepared.prove(&session, &(u, v), &x);
        prepared
            .verify(&session, &(u, v), &proof)
            .expect("verify under correct key");
    }

    /// A proof produced under (g, h_alice) cannot be redirected at
    /// (g, h_bob) — even if (u, v) is consistent under Alice's x. The
    /// committed_index absorption catches it (transcripts diverge).
    #[test]
    fn dleq_proof_does_not_cross_keys() {
        let session = spongefish::session!("dleq test");
        let (g, x_alice, h_alice) = keygen();
        let (_, _x_bob, h_bob) = keygen();

        let alice = dsfs::non_interactive_argument(Dleq::<G>::default(), dsfs::Keccak::default())
            .prepare(&(g, h_alice));
        let bob = dsfs::non_interactive_argument(Dleq::<G>::default(), dsfs::Keccak::default())
            .prepare(&(g, h_bob));
        assert_ne!(alice.committed_index(), bob.committed_index());

        // Alice produces a valid DLEQ for (u, u^x_alice).
        let u = G::generator() * F::rand(&mut OsRng);
        let v_alice = u * x_alice;
        let proof = alice.prove(&session, &(u, v_alice), &x_alice);

        // Bob's prepared wrapper rejects — the bound public key differs.
        assert!(bob.verify(&session, &(u, v_alice), &proof).is_err());
    }

    /// Mismatching (u, v) — i.e., v != u^x — must be rejected by the
    /// honest verifier under the correct key. This exercises the
    /// algebraic check (the second equation u^r == K2 + v*c fails).
    #[test]
    fn dleq_rejects_inconsistent_pair() {
        let session = spongefish::session!("dleq test");
        let (g, x, h) = keygen();
        let prepared =
            dsfs::non_interactive_argument(Dleq::<G>::default(), dsfs::Keccak::default())
                .prepare(&(g, h));

        let u = G::generator() * F::rand(&mut OsRng);
        let v_wrong = u * F::rand(&mut OsRng); // not u^x
        let proof = prepared.prove(&session, &(u, v_wrong), &x);
        assert!(prepared.verify(&session, &(u, v_wrong), &proof).is_err());
    }

    /// Generic-consumer test: `Preprocessed` lets a single function pull
    /// preprocessing keys off any prepared wrapper.
    #[test]
    fn preprocessed_capability_reaches_dleq_key_generically() {
        fn vk_bytes<P: Preprocessed>(p: &P) -> Vec<u8> {
            p.committed_index().as_bytes().to_vec()
        }
        let (g, _x, h) = keygen();
        let prepared = dsfs::non_interactive_argument::<_, [u8; 64], _>(
            Dleq::<G>::default(),
            dsfs::Keccak::default(),
        )
        .prepare(&(g, h));
        let bytes = vk_bytes(&prepared);
        assert!(bytes.starts_with(b"dleq:vk:v1"));
    }
}
