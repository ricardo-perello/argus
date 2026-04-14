//! Regenerates sigma_Keccak1600_BLS12381.json after a transcript API change.
//! Run with: cargo run -p sigma-bridge --example update_keccak_vectors
//! Delete this file after use.

use std::fs;

use bls12_381::G1Projective as Bls12381G1;
use group::{ff::PrimeField, prime::PrimeGroup, Group};
use serde::{Deserialize, Serialize};
use serde_with::{hex, serde_as};
use spongefish::{protocol_id as spongefish_protocol_id, Decoding, Encoding, NargDeserialize, NargSerialize};
use sigma_proofs::{linear_relation::CanonicalLinearRelation, traits::ScalarRng, MultiScalarMul};

#[serde_as]
#[derive(Debug, Deserialize, Serialize)]
struct HexBytes(#[serde_as(as = "hex::Hex")] Vec<u8>);

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

struct FixedScalarRng(std::vec::IntoIter<Vec<u8>>);

impl FixedScalarRng {
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

impl ScalarRng for FixedScalarRng {
    fn random_scalars<G: Group, const N: usize>(&mut self) -> [G::Scalar; N]
    where
        G::Scalar: PrimeField,
    {
        std::array::from_fn(|_| self.next_scalar::<G>())
    }

    fn random_scalars_vec<G: Group>(&mut self, n: usize) -> Vec<G::Scalar>
    where
        G::Scalar: PrimeField,
    {
        (0..n).map(|_| self.next_scalar::<G>()).collect()
    }
}

fn decode_scalars<G>(hex_scalars: &[Vec<u8>]) -> Vec<G::Scalar>
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

fn update_file<G>(path: &str)
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize + MultiScalarMul,
    G::Scalar: Encoding<[u8]> + NargSerialize + NargDeserialize + PrimeField + Decoding<[u8]>,
{
    let json = fs::read_to_string(path).expect("read json");
    let mut vectors: Vec<KeccakVector> = serde_json::from_str(&json).expect("parse json");

    for v in &mut vectors {
        let instance = CanonicalLinearRelation::<G>::from_label(&v.statement)
            .unwrap_or_else(|_| panic!("from_label failed for {}", v.protocol));
        let witness = decode_scalars::<G>(&v.witness);
        let protocol_domain =
            spongefish_protocol_id(core::format_args!("{}", v.ciphersuite));
        let mut rng = FixedScalarRng(v.randomness.clone().into_iter());

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
    println!("Updating sigma_Keccak1600_BLS12381 vectors...");
    update_file::<Bls12381G1>(
        "crates/sigma-bridge/tests/testdata/sigma_Keccak1600_BLS12381.json",
    );
}
