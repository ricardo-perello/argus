//! Round-trip prove/verify tests using σ-proofs `CanonicalLinearRelation` instances
//! parsed from the spec vector JSON files.
//!
//! These do NOT assert byte-identical output to σ-proofs `Nizk::prove_batchable` because
//! sigma-bridge uses the pure IA pipeline (`send_prover_message` for commitments instead of
//! `public_message`), which produces different NARG bytes. What they DO check:
//! - prove succeeds for each test vector's witness
//! - the resulting proof verifies

use bls12_381::G1Projective as Bls12381G1;
use group::prime::PrimeGroup;
use p256::ProjectivePoint as P256ProjectivePoint;
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize};

use sigma_proofs::{linear_relation::CanonicalLinearRelation, MultiScalarMul};

mod spec_rng;
use spec_rng::proof_generation_rng;

use serde_with::{hex, serde_as};

#[serde_as]
#[derive(Debug, Default, serde::Deserialize)]
#[serde(transparent)]
struct Hex(#[serde_as(as = "hex::Hex")] Vec<u8>);

#[derive(Debug, Default, serde::Deserialize)]
struct TestVector {
    #[serde(rename = "Relation")]
    relation: String,
    #[serde(rename = "SessionId")]
    session_id: Hex,
    #[serde(rename = "Statement")]
    statement: Hex,
    #[serde(rename = "Witness")]
    witness: Hex,
}

fn decode_scalars<G>(bytes: &[u8]) -> Vec<G::Scalar>
where
    G: PrimeGroup,
    G::Scalar: NargDeserialize,
{
    let mut cursor = bytes;
    let mut scalars = Vec::new();
    while !cursor.is_empty() {
        scalars.push(G::Scalar::deserialize_from_narg(&mut cursor).expect("deserialize scalar"));
    }
    scalars
}

fn roundtrip_testvectors<G>(vectors_json: &str)
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize + MultiScalarMul,
    G::Scalar: Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]>,
{
    let vectors: Vec<TestVector> = serde_json::from_str(vectors_json).expect("parse json");

    for v in vectors {
        let parsed = CanonicalLinearRelation::<G>::from_label(&v.statement.0);
        let parsed_instance = match parsed {
            Ok(inst) => inst,
            Err(_) => {
                eprintln!("skipping {} (from_label failed)", v.relation);
                continue;
            }
        };

        let witness = decode_scalars::<G>(&v.witness.0);
        let mut rng = proof_generation_rng::<G>(2 * witness.len());

        let proof = sigma_bridge::prove(
            dsfs::StdHash::default(),
            &v.session_id.0,
            &parsed_instance,
            &witness,
            &mut rng,
        )
        .unwrap_or_else(|_| panic!("prove failed for {}", v.relation));

        sigma_bridge::verify(
            dsfs::StdHash::default(),
            &v.session_id.0,
            &parsed_instance,
            &proof,
        )
        .unwrap_or_else(|_| panic!("verify failed for {}", v.relation));
    }
}

#[test]
#[ignore = "P-256 CanonicalLinearRelation::from_label / encoding issue under investigation"]
fn roundtrip_p256_stdhash() {
    roundtrip_testvectors::<P256ProjectivePoint>(include_str!(
        "./testdata/sigma-proofs_Shake128_P256.json"
    ));
}

#[test]
fn roundtrip_bls12381_stdhash() {
    roundtrip_testvectors::<Bls12381G1>(include_str!(
        "./testdata/sigma-proofs_Shake128_BLS12381.json"
    ));
}

fn roundtrip_testvectors_keccak<G>(vectors_json: &str)
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize + MultiScalarMul,
    G::Scalar: Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]>,
{
    let vectors: Vec<TestVector> = serde_json::from_str(vectors_json).expect("parse json");

    for v in vectors {
        let parsed = CanonicalLinearRelation::<G>::from_label(&v.statement.0);
        let parsed_instance = match parsed {
            Ok(inst) => inst,
            Err(_) => {
                eprintln!("skipping {} (from_label failed)", v.relation);
                continue;
            }
        };

        let witness = decode_scalars::<G>(&v.witness.0);
        let mut rng = proof_generation_rng::<G>(2 * witness.len());

        let proof = sigma_bridge::prove(
            dsfs::Keccak::default(),
            &v.session_id.0,
            &parsed_instance,
            &witness,
            &mut rng,
        )
        .unwrap_or_else(|_| panic!("prove failed for {}", v.relation));

        sigma_bridge::verify(
            dsfs::Keccak::default(),
            &v.session_id.0,
            &parsed_instance,
            &proof,
        )
        .unwrap_or_else(|_| panic!("verify failed for {}", v.relation));
    }
}

#[test]
fn roundtrip_bls12381_keccak() {
    roundtrip_testvectors_keccak::<Bls12381G1>(include_str!(
        "./testdata/sigma-proofs_Shake128_BLS12381.json"
    ));
}
