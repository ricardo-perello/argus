//! Bulletproofs inner-product argument (IPA) — monolithic form.
//!
//! Proves knowledge of vectors `a, b in F^n` such that, for public generator
//! vectors `g, h in G^n`, a point `u`, and a commitment `P`:
//!
//! ```text
//!   P = <a, g> + <b, h> + <a, b> * u
//! ```
//!
//! (Bünz–Bootle–Boneh–Poelstra–Wuille–Maxwell, S&P 2018, Protocol 1.) This is
//! the cleanest possible fit for Argus: pure public-coin message passing, **no
//! commitment openings / no oracle**. Each round the prover sends two group
//! elements `L, R`; the verifier replies with one challenge `x`; both fold their
//! length-`n` vectors to `n/2`. After `log2(n)` rounds the witness is two
//! scalars, sent in the clear, so the proof is `O(log n)`.
//!
//! Protocol 1 is not zero-knowledge (the folded `a, b` are revealed); the
//! security metadata tracks soundness only. For the zero-knowledge variant see
//! the `bulletproof_range` example; for the reduction view see
//! `bulletproof_ipa_reduction`.
//!
//! Modes:
//!   (default)  DSFS (non-interactive)
//!   --live     interactive via live-channel (two threads)

use std::thread;

use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::PrimeField;
use ark_std::log2;
use rand::rngs::OsRng;
use spongefish_dsfs as dsfs;

use argus_examples::bulletproofs::{
    IpaInstance, IpaWitness, ipa_prove_core, ipa_round_error, ipa_verify_core, random_statement,
};
use ia_core::prelude::*;
use ia_core::{
    ArgumentSecurity, Decoding, Deserialize, Encoding, ProverChannel, SecurityErrorBound,
    SecurityProfile, VerificationResult, VerifierChannel,
};

// ---------------------------------------------------------------------------
// Protocol object
// ---------------------------------------------------------------------------

struct BulletproofIpaProver<G: CurveGroup>(core::marker::PhantomData<G>);
struct BulletproofIpaVerifier<G: CurveGroup>(core::marker::PhantomData<G>);

impl<G: CurveGroup> Default for BulletproofIpaProver<G> {
    fn default() -> Self {
        Self(core::marker::PhantomData)
    }
}

impl<G: CurveGroup> Default for BulletproofIpaVerifier<G> {
    fn default() -> Self {
        Self(core::marker::PhantomData)
    }
}

ia_core::impl_interactive_argument! {
    impl<G> {
        prover: BulletproofIpaProver<G>,
        verifier: BulletproofIpaVerifier<G>,
    }
    where
        G: CurveGroup + PrimeGroup + Encoding + Deserialize,
        G::ScalarField: PrimeField + Encoding + Decoding + Deserialize,
    {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            ia_core::pad_protocol_id(b"bulletproofs-ipa")
        }

        type Instance = IpaInstance<G>;
        type Witness = IpaWitness<G::ScalarField>;

        fn prove<P: ProverChannel<Unit = u8>>(
            &self,
            ch: &mut P,
            instance: &IpaInstance<G>,
            witness: &IpaWitness<G::ScalarField>,
        ) {
            ipa_prove_core(
                ch,
                instance.g.clone(),
                instance.h.clone(),
                instance.u,
                witness.a.clone(),
                witness.b.clone(),
            );
        }

        fn verify<V: VerifierChannel<Unit = u8>>(
            &self,
            ch: &mut V,
            instance: &IpaInstance<G>,
        ) -> VerificationResult<()> {
            ipa_verify_core(ch, instance.g.clone(), instance.h.clone(), instance.u, instance.p)
        }
    }
}

impl<G> ArgumentSecurity for BulletproofIpaVerifier<G>
where
    G: CurveGroup + PrimeGroup + Encoding + Deserialize,
    G::ScalarField: PrimeField + Encoding + Decoding + Deserialize,
{
    type InstanceParams = usize; // log2(n) = number of rounds
    type InstanceBound = usize;

    fn instance_security_params(&self, instance: &Self::Instance) -> usize {
        log2(instance.g.len()) as usize
    }

    fn instance_bound_for_instance_params(&self, params: &usize) -> usize {
        *params
    }

    fn profile_for_instance_params(&self, params: &usize) -> SecurityProfile {
        ipa_profile::<G::ScalarField>(*params)
    }

    fn profile_for_instance_bound(&self, bound: &usize) -> SecurityProfile {
        ipa_profile::<G::ScalarField>(*bound)
    }
}

fn ipa_profile<F: PrimeField>(log_n: usize) -> SecurityProfile {
    let per_round = ipa_round_error::<F>();
    let rbr: Vec<SecurityErrorBound> = (0..log_n)
        .map(|_| SecurityErrorBound::new(move |_t| per_round))
        .collect();

    SecurityProfile {
        plain_soundness_error: SecurityErrorBound::new(move |_t| (log_n as f64) * per_round),
        rbr_soundness_errors: rbr.clone(),
        rbr_knowledge_soundness_errors: rbr,
        // Protocol 1 is not zero-knowledge; this profile tracks soundness only.
        hvzk_error: SecurityErrorBound::zero(),
        verifier_challenge_lengths: vec![1; log_n],
    }
}

// ---------------------------------------------------------------------------
// Demo runners
// ---------------------------------------------------------------------------

type Demo = ark_curve25519::EdwardsProjective;

fn run_dsfs(n: usize) {
    println!("=== Bulletproofs IPA (DSFS / non-interactive), n = {n} ===\n");
    let (instance, witness) = random_statement::<Demo>(n, &mut OsRng);
    let session = spongefish::session!("bulletproofs ipa example");
    let prover = dsfs::plain_non_interactive_argument_prover(
        BulletproofIpaProver::<Demo>::default(),
        dsfs::Keccak::default(),
    );
    let verifier = dsfs::plain_non_interactive_argument_verifier(
        BulletproofIpaVerifier::<Demo>::default(),
        dsfs::Keccak::default(),
    );
    let narg = prover.prove(&session, &instance, &witness);
    println!(
        "Proof: {} bytes ({} rounds)",
        narg.as_bytes().len(),
        log2(n)
    );
    verifier
        .verify(&session, &instance, &narg)
        .expect("verification failed");
    println!("Verification succeeded");
}

fn run_live(n: usize) {
    println!("=== Bulletproofs IPA (live / interactive), n = {n} ===\n");
    let (instance, witness) = random_statement::<Demo>(n, &mut OsRng);
    let (mut prover_ch, mut verifier_ch) = live_channel::channel_pair();
    let prover_instance = instance.clone();
    let prover = thread::spawn(move || {
        BulletproofIpaProver::<Demo>::default().prove(&mut prover_ch, &prover_instance, &witness);
        println!("[Prover]   Done.");
    });
    let verifier = thread::spawn(move || {
        let r = BulletproofIpaVerifier::<Demo>::default().verify(&mut verifier_ch, &instance);
        println!(
            "[Verifier] {}",
            if r.is_ok() {
                "Verification succeeded!"
            } else {
                "FAILED."
            }
        );
        r
    });
    prover.join().unwrap();
    verifier.join().unwrap().expect("live verification failed");
}

fn main() {
    let live = std::env::args().any(|a| a == "--live");
    if live {
        run_live(8);
    } else {
        run_dsfs(8);
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
    fn ipa_dsfs_roundtrip() {
        for &n in &[1usize, 2, 4, 8, 16] {
            let (instance, witness) = random_statement::<G>(n, &mut OsRng);
            let session = spongefish::session!("bulletproofs ipa test");
            let prover = dsfs::plain_non_interactive_argument_prover(
                BulletproofIpaProver::<G>::default(),
                dsfs::Keccak::default(),
            );
            let verifier = dsfs::plain_non_interactive_argument_verifier(
                BulletproofIpaVerifier::<G>::default(),
                dsfs::Keccak::default(),
            );
            let narg = prover.prove(&session, &instance, &witness);
            verifier
                .verify(&session, &instance, &narg)
                .unwrap_or_else(|_| panic!("dsfs verification failed for n = {n}"));
        }
    }

    #[test]
    fn ipa_dsfs_rejects_wrong_commitment() {
        let (mut instance, witness) = random_statement::<G>(8, &mut OsRng);
        instance.p += G::generator();
        let session = spongefish::session!("bulletproofs ipa test");
        let prover = dsfs::plain_non_interactive_argument_prover(
            BulletproofIpaProver::<G>::default(),
            dsfs::Keccak::default(),
        );
        let verifier = dsfs::plain_non_interactive_argument_verifier(
            BulletproofIpaVerifier::<G>::default(),
            dsfs::Keccak::default(),
        );
        let narg = prover.prove(&session, &instance, &witness);
        assert!(verifier.verify(&session, &instance, &narg).is_err());
    }

    #[test]
    fn ipa_live_roundtrip() {
        let (instance, witness) = random_statement::<G>(8, &mut OsRng);
        let (mut prover_ch, mut verifier_ch) = live_channel::channel_pair();
        let prover_instance = instance.clone();
        let prover = thread::spawn(move || {
            BulletproofIpaProver::<G>::default().prove(&mut prover_ch, &prover_instance, &witness);
        });
        let verifier = thread::spawn(move || {
            BulletproofIpaVerifier::<G>::default().verify(&mut verifier_ch, &instance)
        });
        prover.join().unwrap();
        verifier.join().unwrap().expect("live verification failed");
    }

    #[test]
    fn ipa_profile_round_count_tracks_log_n() {
        let ipa = BulletproofIpaVerifier::<G>::default();
        let (instance, _) = random_statement::<G>(16, &mut OsRng);
        let profile = ipa.profile_for_concrete_instance(&instance);
        assert_eq!(profile.rbr_soundness_errors.len(), log2(16) as usize);
        assert_eq!(profile.verifier_challenge_lengths, vec![1; 4]);
    }

    #[test]
    fn ipa_narg_soundness_above_128_bits() {
        let ipa = BulletproofIpaVerifier::<G>::default();
        let (instance, _) = random_statement::<G>(8, &mut OsRng);
        let narg = dsfs::security_for_concrete_instance(&ipa, &instance);
        assert!(narg.soundness_bits(1 << 40) > 128.0);
        let _ = F::MODULUS_BIT_SIZE;
    }
}
