//! Golden-vector tests for σ-proofs compatibility (batchable proofs, PR #130+).
//!
//! `sigma-proofs::Nizk` uses spongefish `std_prover` / `std_verifier` (SHAKE128) with the same
//! `DomainSeparator::derive` inputs as [`sigma_bridge::prove`] when using [`dsfs::StdHash`].
//!
//! The Shake128 vectors (`sigma-proofs_Shake128_BLS12381.json`) pin expected `"Batchable Proof"`
//! bytes for this workspace’s transcript layout, verified against both BLS12-381 and P-256.
//!
//! `sigma_Keccak1600_BLS12381.json`: uses [`sigma_bridge::prove_with_protocol_domain`] with
//! `StdHash` and the `ciphersuite` string as an explicit 64-byte protocol domain tag. Vectors
//! regenerated for spongefish 0.7.0 (`DomainSeparator::derive`).

use bls12_381::G1Projective as Bls12381G1;
use group::{ff::PrimeField, prime::PrimeGroup};
use p256::ProjectivePoint as P256ProjectivePoint;
use spongefish::dsfs::{self, SpongeInfo, StdHash};
use spongefish::{
    Decoding, DomainSeparator, Encoding, NargDeserialize, NargSerialize,
    protocol_id as spongefish_protocol_id,
};

use sigma_proofs::{
    MultiScalarMul, errors::Error, linear_relation::CanonicalLinearRelation, traits::ScalarRng,
};

use sigma_bridge::SigmaProtocol;

mod spec_rng;
use spec_rng::{MockScalarRng, proof_generation_rng};

use serde_with::{hex, serde_as};

#[serde_as]
#[derive(Debug, Default, serde::Deserialize)]
#[serde(transparent)]
struct Hex(#[serde_as(as = "hex::Hex")] Vec<u8>);

// ---- StdHash vectors (σ-proofs `Nizk::prove_batchable`, byte-identical) ----

#[serde_as]
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
    #[serde(rename = "Batchable Proof")]
    batchable_proof: Hex,
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

fn golden_testvectors_stdhash<G>(vectors_json: &str)
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

        assert_eq!(
            proof, v.batchable_proof.0,
            "batchable proof byte mismatch for {} (σ-proofs Nizk::prove_batchable)",
            v.relation
        );

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
fn golden_p256_stdhash() {
    golden_testvectors_stdhash::<P256ProjectivePoint>(include_str!(
        "./testdata/sigma-proofs_Shake128_P256.json"
    ));
}

#[test]
fn golden_bls12381_stdhash() {
    golden_testvectors_stdhash::<Bls12381G1>(include_str!(
        "./testdata/sigma-proofs_Shake128_BLS12381.json"
    ));
}

/// Same transcript as `sigma_proofs::fiat_shamir::Nizk::prove_batchable`, but with an explicit
/// `protocol_id` (the JSON `ciphersuite` padded to 64 bytes).
fn nizk_prove_batchable_with_protocol_id<G>(
    protocol_id: [u8; 64],
    session_id: &[u8],
    protocol: &CanonicalLinearRelation<G>,
    witness: &Vec<G::Scalar>,
    rng: &mut impl ScalarRng,
) -> Result<Vec<u8>, Error>
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize + MultiScalarMul,
    G::Scalar: Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]>,
{
    let instance_label = protocol.instance_label().as_ref().to_vec();
    let session = sigma_bridge::derive_session_id(session_id);
    let mut transcript =
        DomainSeparator::derive(protocol_id.as_ref(), StdHash::SPONGE_INFO, session.as_ref())
            .instance(&instance_label)
            .std_prover();

    let (commitment, ip_state) = protocol.prover_commit(witness, rng)?;
    let mut commitment_bytes = Vec::new();
    for c in &commitment {
        c.serialize_into_narg(&mut commitment_bytes);
    }
    transcript.public_message(commitment_bytes.as_slice());
    let challenge = transcript.verifier_message::<G::Scalar>();
    let response = protocol.prover_response(ip_state, &challenge)?;
    let mut proof = commitment_bytes;
    for r in &response {
        r.serialize_into_narg(&mut proof);
    }
    Ok(proof)
}

// ---- `sigma_Keccak1600_*.json`: StdHash transcript, explicit randomness (see module docs) ----

#[serde_as]
#[derive(Debug, serde::Deserialize)]
struct KeccakVector {
    protocol: String,
    ciphersuite: String,
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

        let randomness_vecs: Vec<Vec<u8>> = v.randomness.iter().map(|h| h.0.clone()).collect();
        let mut rng = MockScalarRng(randomness_vecs.into_iter());

        let protocol_domain = spongefish_protocol_id(core::format_args!("{}", v.ciphersuite));
        let proof = sigma_bridge::prove_with_protocol_domain(
            dsfs::StdHash::default(),
            &v.session_id.0,
            protocol_domain,
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

        sigma_bridge::verify_with_protocol_domain(
            dsfs::StdHash::default(),
            &v.session_id.0,
            protocol_domain,
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

/// `sigma_bridge::prove_with_protocol_domain` agrees with an inlined `Nizk::prove_batchable` using
/// the same `protocol_id` (e.g. JSON `ciphersuite`).
#[test]
fn prove_with_protocol_domain_matches_inlined_nizk_prove_batchable() {
    let vectors: Vec<KeccakVector> =
        serde_json::from_str(include_str!("./testdata/sigma_Keccak1600_BLS12381.json"))
            .expect("parse json");
    let v = vectors
        .iter()
        .find(|x| x.protocol == "dlog")
        .expect("dlog vector");

    let parsed_instance =
        CanonicalLinearRelation::<Bls12381G1>::from_label(&v.statement.0).expect("from_label");
    let witness: Vec<bls12_381::Scalar> = v
        .witness
        .iter()
        .map(|h| {
            let mut repr = <bls12_381::Scalar as PrimeField>::Repr::default();
            repr.as_mut().copy_from_slice(&h.0);
            bls12_381::Scalar::from_repr(repr)
                .into_option()
                .expect("witness")
        })
        .collect();

    let protocol_id = spongefish_protocol_id(core::format_args!("{}", v.ciphersuite));

    let mut rng1 = MockScalarRng(v.randomness.iter().map(|h| h.0.clone()));
    let mut rng2 = MockScalarRng(v.randomness.iter().map(|h| h.0.clone()));

    let inlined = nizk_prove_batchable_with_protocol_id(
        protocol_id,
        &v.session_id.0,
        &parsed_instance,
        &witness,
        &mut rng1,
    )
    .expect("inlined prove");

    let bridge = sigma_bridge::prove_with_protocol_domain(
        dsfs::StdHash::default(),
        &v.session_id.0,
        protocol_id,
        &parsed_instance,
        &witness,
        &mut rng2,
    )
    .expect("bridge prove");

    assert_eq!(inlined, bridge);
}
