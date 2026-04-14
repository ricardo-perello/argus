//! Roundtrip tests for `SigmaIA<S>` via the full DSFS pipeline.
//!
//! After the Stage 1 domain-separation refactor, `SigmaIA`'s `protocol_id(&self)`
//! returns the full 64-byte `protocol_identifier()` from the underlying sigma
//! protocol. DSFS compacts it (Stage 1: BLAKE3) into the 32-byte domain separator slot.

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use rand_core::SeedableRng;

use ia_core::InteractiveArgument;
use sigma_bridge::{SigmaIA, SigmaProtocol};
use sigma_proofs::linear_relation::CanonicalLinearRelation;
use sigma_proofs::LinearRelation;

fn make_schnorr() -> (SigmaIA<CanonicalLinearRelation<RistrettoPoint>>, Vec<Scalar>) {
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
    (SigmaIA(protocol), witness)
}

#[test]
fn sigmaia_dsfs_roundtrip() {
    let (instance, witness) = make_schnorr();
    let commit_seed = [7u8; 32];
    let sigma_witness = (witness, commit_seed);

    let session = spongefish::session!("sigmaia-roundtrip-test");

    let proof = dsfs::prove(&instance, session, &instance, &sigma_witness);
    dsfs::verify(&instance, session, &instance, &proof).expect("verification must succeed");
}

#[test]
fn sigmaia_protocol_id_is_full_sigma_proofs_identifier() {
    let (instance, _) = make_schnorr();

    // SigmaIA::protocol_id(&self) now returns the full 64-byte sigma-proofs identifier
    // (as an `impl AsRef<[u8]>`), not the first 32 bytes.
    let full_id = instance.0.protocol_identifier();
    let ia_id = instance.protocol_id();

    assert_eq!(
        ia_id.as_ref(),
        &full_id[..],
        "SigmaIA::protocol_id must return the full sigma-proofs identifier"
    );
}
