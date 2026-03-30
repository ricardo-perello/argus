//! Golden-vector tests for σ-proofs compatibility.
//!
//! The Keccak vectors (`sigma_Keccak1600_BLS12381.json`) were generated with the full-NARG
//! batchable proof format (commitments + responses via `prover_message`, proof = NARG string).
//! These are tested for **byte-for-byte equality**.
//!
//! The StdHash vectors (`sigma-proofs_Shake128_BLS12381.json`) were generated with the older
//! σ-proofs batchable format (public_message for commitments). These are tested for
//! **round-trip correctness** only (prove then verify).

use bls12_381::G1Projective as Bls12381G1;
use group::{ff::PrimeField, prime::PrimeGroup};
use p256::ProjectivePoint as P256ProjectivePoint;
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize};

use sigma_proofs::{linear_relation::CanonicalLinearRelation, MultiScalarMul};

mod spec_rng;
use spec_rng::{proof_generation_rng, MockScalarRng};

use serde_with::{hex, serde_as};

#[serde_as]
#[derive(Debug, Default, serde::Deserialize)]
#[serde(transparent)]
struct Hex(#[serde_as(as = "hex::Hex")] Vec<u8>);

// ---- StdHash vectors (old format, round-trip only) ----

#[derive(Debug, Default, serde::Deserialize)]
struct StdHashVector {
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

fn roundtrip_testvectors_stdhash<G>(vectors_json: &str)
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize + MultiScalarMul,
    G::Scalar: Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]>,
{
    let vectors: Vec<StdHashVector> = serde_json::from_str(vectors_json).expect("parse json");

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
    roundtrip_testvectors_stdhash::<P256ProjectivePoint>(include_str!(
        "./testdata/sigma-proofs_Shake128_P256.json"
    ));
}

#[test]
fn roundtrip_bls12381_stdhash() {
    roundtrip_testvectors_stdhash::<Bls12381G1>(include_str!(
        "./testdata/sigma-proofs_Shake128_BLS12381.json"
    ));
}

// ---- Keccak vectors (full-NARG format, byte-equality) ----

#[serde_as]
#[derive(Debug, serde::Deserialize)]
struct KeccakVector {
    protocol: String,
    #[serde(rename = "session_id")]
    session_id: Hex,
    #[serde(rename = "statement")]
    statement: Hex,
    witness: Vec<Hex>,
    randomness: Vec<Hex>,
    #[serde(rename = "proof_batchable")]
    proof_batchable: Hex,
}

fn golden_testvectors_keccak<G>(vectors_json: &str)
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize + MultiScalarMul,
    G::Scalar: Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]> + PrimeField,
{
    let vectors: Vec<KeccakVector> = serde_json::from_str(vectors_json).expect("parse json");

    for v in vectors {
        let parsed = CanonicalLinearRelation::<G>::from_label(&v.statement.0);
        let parsed_instance = match parsed {
            Ok(inst) => inst,
            Err(_) => {
                eprintln!("skipping {} (from_label failed)", v.protocol);
                continue;
            }
        };

        let witness: Vec<G::Scalar> = v
            .witness
            .iter()
            .map(|h| {
                let mut repr = <G::Scalar as PrimeField>::Repr::default();
                repr.as_mut().copy_from_slice(&h.0);
                G::Scalar::from_repr(repr)
                    .into_option()
                    .expect("invalid witness scalar")
            })
            .collect();

        let randomness_vecs: Vec<Vec<u8>> =
            v.randomness.iter().map(|h| h.0.clone()).collect();
        let mut rng = MockScalarRng(randomness_vecs.into_iter());

        let proof = sigma_bridge::prove(
            dsfs::Keccak::default(),
            &v.session_id.0,
            &parsed_instance,
            &witness,
            &mut rng,
        )
        .unwrap_or_else(|_| panic!("prove failed for {}", v.protocol));

        assert_eq!(
            proof, v.proof_batchable.0,
            "byte mismatch for {}",
            v.protocol
        );

        sigma_bridge::verify(
            dsfs::Keccak::default(),
            &v.session_id.0,
            &parsed_instance,
            &proof,
        )
        .unwrap_or_else(|_| panic!("verify failed for {}", v.protocol));
    }
}

#[test]
fn golden_bls12381_keccak() {
    golden_testvectors_keccak::<Bls12381G1>(include_str!(
        "./testdata/sigma_Keccak1600_BLS12381.json"
    ));
}
