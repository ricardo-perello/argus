//! Smoke test: `SigmaIA<ComposedRelation<G>>` round-trips through DSFS after spongefish
//! `DomainSeparator::derive` (variable-length protocol id from the composition tree).

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use rand_core::SeedableRng;

use ia_core::prelude::*;
use sigma_bridge::{SigmaIA, SigmaIAProver, SigmaIAVerifier};
use sigma_proofs::composition::{ComposedRelation, ComposedWitness};
use sigma_proofs::linear_relation::{CanonicalLinearRelation, LinearRelation};
use spongefish_dsfs as dsfs;

fn make_schnorr() -> (CanonicalLinearRelation<RistrettoPoint>, Vec<Scalar>) {
    let mut rel = LinearRelation::<RistrettoPoint>::new();
    let [var_x] = rel.allocate_scalars::<1>();
    let [var_g] = rel.allocate_elements::<1>();
    rel.allocate_eq(var_g * var_x);
    rel.set_elements([(var_g, RISTRETTO_BASEPOINT_POINT)]);

    let mut witness_rng = rand_chacha::ChaCha20Rng::from_seed([43u8; 32]);
    let x = Scalar::random(&mut witness_rng);
    let witness = vec![x];
    rel.compute_image(&witness).expect("compute image");

    let protocol = rel.canonical().expect("canonical");
    (protocol, witness)
}

#[test]
fn sigmaia_composed_and_dsfs_roundtrip() {
    let (r1, w1) = make_schnorr();
    let (r2, w2) = make_schnorr();

    let a: ComposedRelation<RistrettoPoint> = r1.into();
    let b: ComposedRelation<RistrettoPoint> = r2.into();
    let composed = ComposedRelation::<RistrettoPoint>::and([a, b]);

    let w1c: ComposedWitness<RistrettoPoint> = w1.into();
    let w2c: ComposedWitness<RistrettoPoint> = w2.into();
    let witness = ComposedWitness::<RistrettoPoint>::and([w1c, w2c]);

    let ia = SigmaIA(composed);
    let commit_seed = [11u8; 32];
    let sigma_witness = (witness, commit_seed);

    let session = spongefish::session!("composed-relation-smoke");
    let prover = dsfs::argument_prover(
        SigmaIAProver::new(&ia),
        dsfs::Keccak::default(),
    );
    let verifier = dsfs::argument_verifier(
        SigmaIAVerifier::new(&ia),
        dsfs::Keccak::default(),
    );

    let proof = prover.prove(&session, &ia, &sigma_witness);
    verifier
        .verify(&session, &ia, &proof)
        .expect("composed SigmaIA verification must succeed");
}
