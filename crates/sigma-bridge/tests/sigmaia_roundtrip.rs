//! Roundtrip test for `SigmaIA<S>` via the IA channel API.
//!
//! Bypasses `SigmaIA::protocol_id()` (blocked on Q1) by constructing
//! `SpongeProver` / `SpongeVerifier` directly with matching domain setup,
//! then calling `InteractiveArgument::prove` and `verify` on those channels.
//!
//! This validates:
//!   - Q2: commit randomness seed bundled in witness → `ChaCha20Rng::from_seed`
//!   - Q3: `Encoding for SigmaIA<S>` forwards `instance_label()` correctly

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use rand_core::SeedableRng;

use dsfs::{Keccak, SpongeProver, SpongeVerifier, TranscriptSponge};
use ia_core::InteractiveArgument;
use sigma_bridge::{derive_session_id, SigmaIA, SigmaProtocol};
use sigma_proofs::LinearRelation;

#[test]
fn sigmaia_roundtrip_keccak() {
    // --- build the sigma protocol instance ---
    let mut rel = LinearRelation::<RistrettoPoint>::new();
    let [var_x] = rel.allocate_scalars::<1>();
    let [var_g] = rel.allocate_elements::<1>();
    rel.allocate_eq(var_g * var_x);
    rel.set_elements([(var_g, RISTRETTO_BASEPOINT_POINT)]);

    let mut witness_rng = rand_chacha::ChaCha20Rng::from_seed([42u8; 32]);
    let x = Scalar::random(&mut witness_rng);
    let witness = vec![x];
    rel.compute_image(&witness).expect("compute image");

    let protocol = rel.canonical().expect("canonical");

    // Wrap in SigmaIA — the wrapped value is both protocol params and the public instance
    let instance = SigmaIA(protocol);

    // Commit randomness seed (Q2: bundled into witness tuple)
    let commit_seed = [7u8; 32];
    let sigma_witness = (witness, commit_seed);

    // Use the sigma protocol's own identifier as the domain (bypasses Q1 todo!)
    let protocol_id = instance.0.protocol_identifier();
    let session = derive_session_id(b"sigmaia-roundtrip-test");

    // --- prove ---
    let mut prover_ch = SpongeProver::new(
        Keccak::default().prover_state(protocol_id, session, &instance),
    );
    <SigmaIA<_> as InteractiveArgument>::prove(&mut prover_ch, &instance, &sigma_witness);
    let proof = prover_ch.narg_string().to_vec();

    // --- verify ---
    let mut verifier_ch = SpongeVerifier::new(
        Keccak::default().verifier_state(protocol_id, session, &instance, &proof),
    );
    <SigmaIA<_> as InteractiveArgument>::verify(&mut verifier_ch, &instance)
        .expect("SigmaIA verify must succeed");
    verifier_ch.check_eof().expect("no trailing bytes in proof");
}
