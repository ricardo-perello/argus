//! Curve25519 (Ristretto) round-trip prove/verify via sigma-bridge's DSFS IA pipeline.

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use rand_core::SeedableRng;

use sigma_proofs::LinearRelation;
use spongefish_dsfs as dsfs;

#[test]
fn curve25519_round_trip_stdhash() {
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

    let mut proof_rng = rand_chacha::ChaCha20Rng::from_seed([7u8; 32]);

    let proof = sigma_bridge::prove(
        dsfs::StdHash::default(),
        b"curve25519-session",
        &protocol,
        &witness,
        &mut proof_rng,
    )
    .expect("prove");

    sigma_bridge::verify(
        dsfs::StdHash::default(),
        b"curve25519-session",
        &protocol,
        &proof,
    )
    .expect("verify");
}

#[test]
fn curve25519_round_trip_keccak() {
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

    let mut proof_rng = rand_chacha::ChaCha20Rng::from_seed([7u8; 32]);

    let proof = sigma_bridge::prove(
        dsfs::Keccak::default(),
        b"curve25519-session",
        &protocol,
        &witness,
        &mut proof_rng,
    )
    .expect("prove");

    sigma_bridge::verify(
        dsfs::Keccak::default(),
        b"curve25519-session",
        &protocol,
        &proof,
    )
    .expect("verify");
}
