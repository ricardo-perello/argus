//! Regenerates sigma-bridge golden-vector proof bytes after a transcript API change.
//! Run with: cargo run -p sigma-bridge --example update_keccak_vectors

use std::fs;

use bls12_381::G1Projective as Bls12381G1;
use core::array::from_fn;
use group::{Group, ff::PrimeField, prime::PrimeGroup};
use p256::ProjectivePoint as P256ProjectivePoint;
use serde::{Deserialize, Serialize};
use serde_with::{hex, serde_as};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sigma_proofs::{MultiScalarMul, linear_relation::CanonicalLinearRelation, traits::ScalarRng};
use spongefish::{
    Decoding, Encoding, NargDeserialize, NargSerialize, protocol_id as spongefish_protocol_id,
};
use spongefish_dsfs as dsfs;

#[serde_as]
#[derive(Debug, Deserialize, Serialize)]
struct StdHashVector {
    #[serde(rename = "Relation")]
    relation: String,
    #[serde(rename = "Ciphersuite")]
    ciphersuite: String,
    #[serde_as(as = "hex::Hex")]
    #[serde(rename = "SessionId")]
    session_id: Vec<u8>,
    #[serde_as(as = "hex::Hex")]
    #[serde(rename = "Statement")]
    statement: Vec<u8>,
    #[serde_as(as = "hex::Hex")]
    #[serde(rename = "Witness")]
    witness: Vec<u8>,
    #[serde_as(as = "hex::Hex")]
    #[serde(rename = "Proof")]
    proof: Vec<u8>,
    #[serde_as(as = "hex::Hex")]
    #[serde(rename = "Batchable Proof")]
    batchable_proof: Vec<u8>,
}

#[serde_as]
#[derive(Debug, Deserialize, Serialize)]
struct KeccakVector {
    protocol: String,
    ciphersuite: String,
    #[serde_as(as = "hex::Hex")]
    session_id: Vec<u8>,
    #[serde_as(as = "hex::Hex")]
    statement: Vec<u8>,
    #[serde_as(as = "Vec<hex::Hex>")]
    witness: Vec<Vec<u8>>,
    #[serde_as(as = "Vec<hex::Hex>")]
    randomness: Vec<Vec<u8>>,
    #[serde_as(as = "hex::Hex")]
    proof_batchable: Vec<u8>,
}

struct MockScalarRng<I: Iterator<Item = Vec<u8>>>(I);

impl<I: Iterator<Item = Vec<u8>>> MockScalarRng<I> {
    fn next_scalar<G: Group>(&mut self) -> G::Scalar
    where
        G::Scalar: PrimeField,
    {
        let bytes = self.0.next().expect("randomness exhausted");
        let mut repr = <G::Scalar as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(&bytes);
        G::Scalar::from_repr(repr).expect("invalid scalar")
    }
}

impl<I: Iterator<Item = Vec<u8>>> ScalarRng for MockScalarRng<I> {
    fn random_scalars<G: Group, const N: usize>(&mut self) -> [G::Scalar; N]
    where
        G::Scalar: PrimeField,
    {
        from_fn(|_| self.next_scalar::<G>())
    }

    fn random_scalars_vec<G: Group>(&mut self, n: usize) -> Vec<G::Scalar>
    where
        G::Scalar: PrimeField,
    {
        (0..n).map(|_| self.next_scalar::<G>()).collect()
    }
}

fn proof_generation_rng<G>(count: usize) -> MockScalarRng<std::vec::IntoIter<Vec<u8>>>
where
    G: PrimeGroup,
    G::Scalar: Decoding<[u8]> + PrimeField,
    <G::Scalar as Decoding<[u8]>>::Repr: Default + AsMut<[u8]>,
{
    MockScalarRng(test_drng_scalars::<G>(b"proof_generation_seed", count).into_iter())
}

fn test_drng_scalars<G>(seed_label: &[u8], count: usize) -> Vec<Vec<u8>>
where
    G: PrimeGroup,
    G::Scalar: Decoding<[u8]> + PrimeField,
    <G::Scalar as Decoding<[u8]>>::Repr: Default + AsMut<[u8]>,
{
    let mut drng = TestDrng::from_seed(seed_label);
    (0..count)
        .map(|_| drng.random_scalar_bytes::<G>())
        .collect()
}

struct TestDrng {
    state: sha3::Shake128,
    squeeze_offset: usize,
}

impl TestDrng {
    fn from_seed(seed_label: &[u8]) -> Self {
        let mut initial_block = [0u8; 168];
        let domain = b"sigma-proofs/TestDRNG/SHAKE128";
        initial_block[..domain.len()].copy_from_slice(domain);

        let mut state = sha3::Shake128::default();
        state.update(&initial_block);
        state.update(&fixed_seed(seed_label));
        Self {
            state,
            squeeze_offset: 0,
        }
    }

    fn random_scalar_bytes<G>(&mut self) -> Vec<u8>
    where
        G: PrimeGroup,
        G::Scalar: Decoding<[u8]> + PrimeField,
        <G::Scalar as Decoding<[u8]>>::Repr: Default + AsMut<[u8]>,
    {
        let mut repr = <G::Scalar as Decoding<[u8]>>::Repr::default();
        let uniform_bytes = self.squeeze(repr.as_mut().len());
        repr.as_mut().copy_from_slice(&uniform_bytes);
        let scalar = G::Scalar::decode(repr);
        scalar.to_repr().as_ref().to_vec()
    }

    fn squeeze(&mut self, length: usize) -> Vec<u8> {
        let end = self.squeeze_offset + length;
        let mut full = vec![0u8; end];
        self.state.clone().finalize_xof().read(&mut full);
        let out = full[self.squeeze_offset..end].to_vec();
        self.squeeze_offset = end;
        out
    }
}

fn fixed_seed(label: &[u8]) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[..label.len()].copy_from_slice(label);
    seed
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

fn decode_prime_field_scalars<G>(hex_scalars: &[Vec<u8>]) -> Vec<G::Scalar>
where
    G: PrimeGroup,
    G::Scalar: PrimeField,
{
    hex_scalars
        .iter()
        .map(|bytes| {
            let mut repr = <G::Scalar as PrimeField>::Repr::default();
            repr.as_mut().copy_from_slice(bytes);
            G::Scalar::from_repr(repr).expect("invalid witness scalar")
        })
        .collect()
}

fn update_stdhash_file<G>(path: &str)
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize + MultiScalarMul,
    G::Scalar: Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]> + PrimeField,
    <G::Scalar as Decoding<[u8]>>::Repr: Default + AsMut<[u8]>,
{
    let json = fs::read_to_string(path).expect("read json");
    let mut vectors: Vec<StdHashVector> = serde_json::from_str(&json).expect("parse json");

    for v in &mut vectors {
        let instance = CanonicalLinearRelation::<G>::from_label(&v.statement)
            .unwrap_or_else(|_| panic!("from_label failed for {}", v.relation));
        let witness = decode_scalars::<G>(&v.witness);
        let mut rng = proof_generation_rng::<G>(2 * witness.len());

        let proof = sigma_bridge::prove(
            dsfs::StdHash::default(),
            &v.session_id,
            &instance,
            &witness,
            &mut rng,
        )
        .unwrap_or_else(|_| panic!("prove failed for {}", v.relation));

        v.batchable_proof = proof;
        println!("  updated: {}", v.relation);
    }

    let new_json = serde_json::to_string_pretty(&vectors).expect("serialize");
    fs::write(path, new_json + "\n").expect("write json");
    println!("wrote {path}");
}

fn update_keccak_file<G>(path: &str)
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize + MultiScalarMul,
    G::Scalar: Encoding<[u8]> + NargSerialize + NargDeserialize + PrimeField + Decoding<[u8]>,
{
    let json = fs::read_to_string(path).expect("read json");
    let mut vectors: Vec<KeccakVector> = serde_json::from_str(&json).expect("parse json");

    for v in &mut vectors {
        let instance = CanonicalLinearRelation::<G>::from_label(&v.statement)
            .unwrap_or_else(|_| panic!("from_label failed for {}", v.protocol));
        let witness = decode_prime_field_scalars::<G>(&v.witness);
        let protocol_domain = spongefish_protocol_id(core::format_args!("{}", v.ciphersuite));
        let mut rng = MockScalarRng(v.randomness.clone().into_iter());

        let proof = sigma_bridge::prove_with_protocol_domain(
            dsfs::StdHash::default(),
            &v.session_id,
            protocol_domain,
            &instance,
            &witness,
            &mut rng,
        )
        .unwrap_or_else(|_| panic!("prove failed for {}", v.protocol));

        v.proof_batchable = proof;
        println!("  updated: {}", v.protocol);
    }

    let new_json = serde_json::to_string_pretty(&vectors).expect("serialize");
    fs::write(path, new_json + "\n").expect("write json");
    println!("wrote {path}");
}

fn main() {
    println!("Updating sigma-proofs_Shake128_BLS12381 vectors...");
    update_stdhash_file::<Bls12381G1>(
        "crates/sigma-bridge/tests/testdata/sigma-proofs_Shake128_BLS12381.json",
    );

    println!("Updating sigma-proofs_Shake128_P256 vectors...");
    update_stdhash_file::<P256ProjectivePoint>(
        "crates/sigma-bridge/tests/testdata/sigma-proofs_Shake128_P256.json",
    );

    println!("Updating sigma_Keccak1600_BLS12381 vectors...");
    update_keccak_file::<Bls12381G1>(
        "crates/sigma-bridge/tests/testdata/sigma_Keccak1600_BLS12381.json",
    );
}
