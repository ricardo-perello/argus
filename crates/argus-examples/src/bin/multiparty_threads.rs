//! Multi-party simulation: indexer / prover / verifier on separate threads,
//! exchanging only the bytes a real wire would carry.
//!
//! This is the runtime story behind the keys-as-inputs API (see
//! `docs/keys-as-inputs-preprocessing-presentation.md`):
//!
//! 1. **2-machine plain (Schnorr).** No keys, no indexer. Prover and verifier
//!    each construct the same compiled NIA from the public protocol body and
//!    sponge config. The prover ships `NargProof` bytes over an `mpsc` channel;
//!    the verifier verifies. Per-claim agreement is `[g, h]` (sent OOB; here
//!    we just `Copy` it into each closure).
//!
//! 2. **3-machine preprocessed (DLEQ).** Adds an indexer party that runs
//!    `index` once over the long-term key pair `(g, h = g^x)`. It ships the
//!    `ProverKey` to the prover and the `VerifierKey` to the verifier (each
//!    carries the committed index). Each party then constructs its own PNIA
//!    and wraps it with `Prover` / `Verifier` (the optional role-typed
//!    wrappers). The prover never holds `vk`; the verifier never holds `pk`
//!    or a `prove` method. Per claim, the prover sends `((u, v), proof)`.
//!
//! Run:  cargo run -p argus-examples --bin multiparty_threads

use std::sync::mpsc;
use std::thread;

use ark_curve25519::{EdwardsProjective as G, Fr as F};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::PrimeField;
use ark_std::UniformRand;
use rand::rngs::OsRng;
use spongefish_dsfs as dsfs;

use ia_core::{
    CommittedIndex, CommittedIndexBytes, Decoding, Deserialize, Encoding, NargProof,
    NonInteractiveArgument, PreprocessingCore, Prover, ProverChannel, VerificationError,
    VerificationResult, Verifier, VerifierChannel,
};

// ---------------------------------------------------------------------------
// Schnorr body (plain) — knowledge of `x` such that `h = g * x`.
// ---------------------------------------------------------------------------

struct Schnorr<C: CurveGroup>(core::marker::PhantomData<C>);

impl<C: CurveGroup> Default for Schnorr<C> {
    fn default() -> Self {
        Self(core::marker::PhantomData)
    }
}

ia_core::impl_interactive_argument! {
    impl<C> InteractiveArgument for Schnorr<C>
    where
        C: CurveGroup + PrimeGroup + Encoding + Deserialize,
        C::ScalarField: PrimeField + Encoding + Decoding + Deserialize,
    {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            ia_core::pad_protocol_id(b"multiparty-schnorr")
        }

        type Instance = [C; 2];
        type Witness = C::ScalarField;

        #[allow(non_snake_case)]
        fn prove<P: ProverChannel<Unit = u8>>(
            &self,
            ch: &mut P,
            instance: &Self::Instance,
            witness: &Self::Witness,
        ) {
            let [g, _h] = *instance;
            let x = *witness;
            let k = C::ScalarField::rand(&mut OsRng);
            let K = g * k;
            ch.send_prover_message(&K);
            let c: C::ScalarField = ch.read_verifier_message();
            let r = k + c * x;
            ch.send_prover_message(&r);
        }

        #[allow(non_snake_case)]
        fn verify<V: VerifierChannel<Unit = u8>>(
            &self,
            ch: &mut V,
            instance: &Self::Instance,
        ) -> VerificationResult<()> {
            let [g, h] = *instance;
            let K: C = ch.read_prover_message()?;
            let c: C::ScalarField = ch.send_verifier_message();
            let r: C::ScalarField = ch.read_prover_message()?;
            if g * r == K + h * c {
                Ok(())
            } else {
                Err(VerificationError)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DLEQ body (preprocessed) — Chaum-Pedersen over a long-term key pair (g, h=g^x).
// Per-claim instance is (u, v=u^x); the witness is x.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct DleqKey<C: CurveGroup> {
    g: C,
    h: C,
}

impl<C: CurveGroup + Encoding> CommittedIndex for DleqKey<C> {
    fn committed_index(&self) -> CommittedIndexBytes {
        // Tag + (g || h) — namespaced canonical digest of the verifier key.
        let mut out = Vec::new();
        out.extend_from_slice(b"multiparty-dleq:vk:v1");
        out.extend_from_slice(self.g.encode().as_ref());
        out.extend_from_slice(self.h.encode().as_ref());
        CommittedIndexBytes::new(out)
    }
}

struct Dleq<C: CurveGroup>(core::marker::PhantomData<C>);

impl<C: CurveGroup> Default for Dleq<C> {
    fn default() -> Self {
        Self(core::marker::PhantomData)
    }
}

ia_core::impl_preprocessing_argument! {
    impl<C> PreprocessingInteractiveArgument for Dleq<C>
    where
        C: CurveGroup + PrimeGroup + Encoding + Deserialize,
        C::ScalarField: PrimeField + Encoding + Decoding + Deserialize,
    {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            ia_core::pad_protocol_id(b"multiparty-dleq")
        }

        type Instance = (C, C);
        type Witness = C::ScalarField;
        type Index = (C, C);
        type ProverKey = DleqKey<C>;
        type VerifierKey = DleqKey<C>;

        fn preprocess(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
            let key = DleqKey { g: ix.0, h: ix.1 };
            (key.clone(), key)
        }

        #[allow(non_snake_case)]
        fn prove<P: ProverChannel<Unit = u8>>(
            &self,
            ch: &mut P,
            pk: &DleqKey<C>,
            instance: &(C, C),
            witness: &C::ScalarField,
        ) {
            let DleqKey { g, h: _ } = pk.clone();
            let (u, _v) = *instance;
            let x = *witness;

            let k = C::ScalarField::rand(&mut OsRng);
            let K1 = g * k;
            let K2 = u * k;
            ch.send_prover_message(&K1);
            ch.send_prover_message(&K2);

            let c: C::ScalarField = ch.read_verifier_message();
            let r = k + c * x;
            ch.send_prover_message(&r);
        }

        #[allow(non_snake_case)]
        fn verify<V: VerifierChannel<Unit = u8>>(
            &self,
            ch: &mut V,
            vk: &DleqKey<C>,
            instance: &(C, C),
        ) -> VerificationResult<()> {
            let DleqKey { g, h } = vk.clone();
            let (u, v) = *instance;

            let K1: C = ch.read_prover_message()?;
            let K2: C = ch.read_prover_message()?;
            let c: C::ScalarField = ch.send_verifier_message();
            let r: C::ScalarField = ch.read_prover_message()?;

            if g * r == K1 + h * c && u * r == K2 + v * c {
                Ok(())
            } else {
                Err(VerificationError)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Demo 1 — 2-machine plain Schnorr (no indexer, no keys)
// ---------------------------------------------------------------------------

fn demo_two_machine_plain() {
    println!("=== 2-machine plain Schnorr (NARG over the wire) ===\n");

    // Public statement agreed out-of-band: (g, h = g^x). Only the prover holds x.
    let g = G::generator();
    let x = F::rand(&mut OsRng);
    let h = g * x;
    let session = spongefish::session!("multiparty / plain schnorr");

    // One-way wire: prover -> verifier.
    let (proof_tx, proof_rx) = mpsc::channel::<NargProof>();

    // PROVER machine. Holds the witness `x`. Builds its own compiled NIA from
    // the public body + sponge config; the verifier independently builds the same.
    let prover = thread::spawn(move || {
        let nia =
            dsfs::plain_non_interactive_argument(Schnorr::<G>::default(), dsfs::Keccak::default());
        let proof = nia.prove(&session, &[g, h], &x);
        let n = proof.as_bytes().len();
        proof_tx.send(proof).expect("ship proof");
        println!("  prover  : built and shipped Schnorr proof ({n} bytes)");
    });

    // VERIFIER machine. Holds no witness. Same body + sponge config => same compiled NIA.
    let verifier = thread::spawn(move || {
        let nia =
            dsfs::plain_non_interactive_argument(Schnorr::<G>::default(), dsfs::Keccak::default());
        let proof = proof_rx.recv().expect("recv proof");
        nia.verify(&session, &[g, h], &proof)
            .expect("verifier accepts honest proof");
        println!("  verifier: accepted");
    });

    prover.join().unwrap();
    verifier.join().unwrap();
}

// ---------------------------------------------------------------------------
// Demo 2 — 3-machine preprocessed DLEQ (indexer / prover / verifier)
// ---------------------------------------------------------------------------

fn demo_three_machine_preprocessed() {
    println!("\n=== 3-machine preprocessed DLEQ (indexer / prover / verifier) ===\n");

    const CLAIMS: usize = 3;

    // Long-term DLEQ key pair: secret x stays with the prover; (g, h=g^x) is the
    // public preprocessing input shipped to the indexer.
    let g = G::generator();
    let x = F::rand(&mut OsRng);
    let h = g * x;
    let session = spongefish::session!("multiparty / preprocessed dleq");

    // Three wires:
    //   setup  ──(ProverKey)───► prover     (the prover key; carries the index)
    //   setup  ──(VerifierKey)─► verifier
    //   prover ──((u,v), NargProof)─► verifier
    let (pk_tx, pk_rx) = mpsc::channel::<DleqKey<G>>();
    let (vk_tx, vk_rx) = mpsc::channel::<DleqKey<G>>();
    let (proof_tx, proof_rx) = mpsc::channel::<((G, G), NargProof)>();

    // SETUP / INDEXER machine. Runs once, never touches witnesses.
    let setup = thread::spawn(move || {
        let pnia = dsfs::preprocessing_non_interactive_argument::<_, [u8; 64], _>(
            Dleq::<G>::default(),
            dsfs::Keccak::default(),
        );
        let (prover_key, verifier_key) = pnia.preprocess(&(g, h));
        let ci_hex = hex::encode(prover_key.committed_index().as_bytes());
        pk_tx.send(prover_key).expect("ship prover key");
        vk_tx.send(verifier_key).expect("ship verifier key");
        println!("  setup   : ran indexer; shipped ProverKey + VerifierKey");
        println!("            committed_index = 0x{}", &ci_hex[..32]);
    });

    // PROVER machine. Receives only the proving key. Builds its own pnia and a
    // role-typed `Prover` wrapper. The wrapper holds the proving key by
    // reference; there is no path here to ever obtain `vk`.
    let prover = thread::spawn(move || {
        let pnia = dsfs::preprocessing_non_interactive_argument::<_, [u8; 64], _>(
            Dleq::<G>::default(),
            dsfs::Keccak::default(),
        );
        let prover_key = pk_rx.recv().expect("recv prover key");
        let prover_view = Prover::new(&pnia, &prover_key);

        for i in 0..CLAIMS {
            // Per-session blinding: a fresh (u, v = u^x) pair.
            let u = G::generator() * F::rand(&mut OsRng);
            let v = u * x;
            let proof = prover_view.prove(&session, &(u, v), &x);
            let n = proof.as_bytes().len();
            proof_tx.send(((u, v), proof)).expect("ship proof");
            println!("  prover  : proof {i} produced and shipped ({n} bytes)");
        }
    });

    // VERIFIER machine. Receives only the verifier key. Builds its own pnia and
    // a `Verifier` wrapper. The wrapper exposes only `.verify` — there is
    // literally no `prove` method on this type.
    let verifier = thread::spawn(move || {
        let pnia = dsfs::preprocessing_non_interactive_argument::<_, [u8; 64], _>(
            Dleq::<G>::default(),
            dsfs::Keccak::default(),
        );
        let verifier_key = vk_rx.recv().expect("recv verifier key");
        let verifier_view = Verifier::new(&pnia, &verifier_key);

        for i in 0..CLAIMS {
            let (instance, proof) = proof_rx.recv().expect("recv proof");
            verifier_view
                .verify(&session, &instance, &proof)
                .expect("verifier accepts honest proof");
            println!("  verifier: accepted proof {i}");
        }
    });

    setup.join().unwrap();
    prover.join().unwrap();
    verifier.join().unwrap();
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
    demo_two_machine_plain();
    demo_three_machine_preprocessed();
}

// ---------------------------------------------------------------------------
// Tests — each demo round-trips honest claims across the simulated machines.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_machine_plain_runs() {
        demo_two_machine_plain();
    }

    #[test]
    fn three_machine_preprocessed_runs() {
        demo_three_machine_preprocessed();
    }
}
