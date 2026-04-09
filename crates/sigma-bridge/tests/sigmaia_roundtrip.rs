//! Roundtrip tests for `SigmaIA<S>` via the full DSFS pipeline.
//!
//! Now that Q1 is resolved (StaticSigmaProtocol gives us a static protocol_id),
//! these tests go through dsfs::prove / dsfs::verify end-to-end.

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

    let proof = dsfs::prove::<SigmaIA<_>>(session, &instance, &sigma_witness);
    dsfs::verify::<SigmaIA<_>>(session, &instance, &proof).expect("verification must succeed");
}

#[test]
fn sigmaia_protocol_id_is_first_32_bytes_of_sigma_proofs_id() {
    let (instance, _) = make_schnorr();

    // SigmaIA::protocol_id() should be first 32 bytes of protocol_identifier()
    let full_id = instance.0.protocol_identifier();
    let ia_id = <SigmaIA<CanonicalLinearRelation<RistrettoPoint>> as InteractiveArgument>::protocol_id();

    assert_eq!(ia_id, full_id[..32], "SigmaIA protocol_id must be first 32 bytes of sigma-proofs identifier");
}
