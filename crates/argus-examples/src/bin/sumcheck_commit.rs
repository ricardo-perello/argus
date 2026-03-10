//! Committed Boolean Sumcheck via the InteractiveArgument + DSFS stack (v2).
//!
//! Protocol:
//! - Prover commits to the full evaluation table evals via a Merkle root.
//! - Run "sumcheck" with bit challenges b_i in {0,1} (derived via the channel).
//!   This collapses the claim to a single table entry evals[idx].
//! - Prover opens the Merkle tree at idx and verifier checks opening + value == claim.

use ark_curve25519::Fr;
use ark_ff::Zero;
use ark_std::UniformRand;
use rand::rngs::OsRng;
use std::io::Cursor;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use ia_core::{
    InteractiveArgument, Prove, ReadProverMessage, ReadVerifierMessage, SendProverMessage,
    SendVerifierMessage, Verify, VerificationError, VerificationResult,
};

use spongefish::Encoding;

use ark_crypto_primitives::crh::sha256::Sha256;
use ark_crypto_primitives::merkle_tree::{
    Config, DigestConverter, LeafParam, MerkleTree, Path, TwoToOneParam,
};

// ---------------------------------------------------------------------------
// Codec types (Encoding/NargDeserialize impls for spongefish -- stays here)
// ---------------------------------------------------------------------------

/// Canonical-framed byte string for variable-length Merkle data.
#[derive(Clone, Default, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
struct Bytes(Vec<u8>);

impl Encoding for Bytes {
    fn encode(&self) -> impl AsRef<[u8]> {
        canonical_to_bytes(self)
    }
}

impl spongefish::NargDeserialize for Bytes {
    fn deserialize_from_narg(buf: &mut &[u8]) -> spongefish::VerificationResult<Self> {
        canonical_from_narg(buf)
    }
}

fn canonical_to_bytes<T: CanonicalSerialize>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    value
        .serialize_compressed(&mut out)
        .expect("canonical serialization must succeed");
    out
}

fn canonical_from_narg<T: CanonicalDeserialize>(
    buf: &mut &[u8],
) -> spongefish::VerificationResult<T> {
    let mut cursor = Cursor::new(*buf);
    let value =
        T::deserialize_compressed(&mut cursor).map_err(|_| spongefish::VerificationError)?;
    let consumed = cursor.position() as usize;
    *buf = &buf[consumed..];
    Ok(value)
}

// ---------------------------------------------------------------------------
// Protocol types
// ---------------------------------------------------------------------------

/// Public instance: root commitment + claimed sum.
#[derive(Clone, Encoding)]
struct Instance {
    n: u32,
    root: Bytes,
    claimed_sum: Fr,
}

/// Opening proof sent as the final prover message.
#[derive(Clone, Encoding, spongefish::NargDeserialize)]
struct OpeningProof {
    idx: u32,
    value: Fr,
    path_bytes: Bytes,
}

// ---------------------------------------------------------------------------
// Merkle tree configuration (SHA-256)
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct Sha256MerkleConfig;

pub struct VecU8DigestToBytes;

impl DigestConverter<Vec<u8>, [u8]> for VecU8DigestToBytes {
    type TargetType = Vec<u8>;

    fn convert(item: Vec<u8>) -> Result<Self::TargetType, ark_crypto_primitives::Error> {
        Ok(item)
    }
}

impl Config for Sha256MerkleConfig {
    type Leaf = [u8];
    type LeafDigest = Vec<u8>;
    type LeafInnerDigestConverter = VecU8DigestToBytes;
    type InnerDigest = Vec<u8>;
    type LeafHash = Sha256;
    type TwoToOneHash = Sha256;
}

// ---------------------------------------------------------------------------
// InteractiveArgument: metadata
// ---------------------------------------------------------------------------

struct CommittedSumcheck;

impl InteractiveArgument for CommittedSumcheck {
    type Instance = Instance;
    type Witness = Vec<Fr>;

    fn protocol_id() -> [u8; 64] {
        spongefish::protocol_id(core::format_args!(
            "committed sumcheck (bit challenges, sha256 merkle)"
        ))
    }
}

// ---------------------------------------------------------------------------
// Prove: linear prover logic against an abstract channel
// ---------------------------------------------------------------------------

impl<P> Prove<P> for CommittedSumcheck
where
    P: SendProverMessage<Bytes>
        + SendProverMessage<Fr>
        + ReadVerifierMessage<u8>
        + SendProverMessage<OpeningProof>,
{
    #[allow(non_snake_case)]
    fn prove(ch: &mut P, instance: &Instance, evals: &Vec<Fr>) {
        let n = instance.n as usize;
        let (tree, root) = Self::build_merkle_tree(evals);
        assert_eq!(root.as_slice(), instance.root.0.as_slice());

        // Commit phase: send Merkle root
        ch.send_prover_message(&instance.root);

        // Sumcheck with bit challenges
        let mut table = evals.to_vec();
        let mut idx: u32 = 0;

        for round in 0..n {
            let mut s0 = Fr::zero();
            let mut s1 = Fr::zero();
            for pair in table.chunks_exact(2) {
                s0 += pair[0];
                s1 += pair[1];
            }

            ch.send_prover_message(&s0);
            ch.send_prover_message(&s1);

            let x: u8 = ch.read_verifier_message();
            let b = x & 1;
            if b == 1 {
                idx |= 1u32 << round;
            }

            let mut next = Vec::with_capacity(table.len() / 2);
            for pair in table.chunks_exact(2) {
                next.push(if b == 0 { pair[0] } else { pair[1] });
            }
            table = next;
        }

        // Opening phase: open committed table at selected index
        let value = evals[idx as usize];
        let path: Path<Sha256MerkleConfig> = tree.generate_proof(idx as usize).unwrap();
        let mut path_bytes = Vec::new();
        path.serialize_compressed(&mut path_bytes).unwrap();

        ch.send_prover_message(&OpeningProof {
            idx,
            value,
            path_bytes: Bytes(path_bytes),
        });
    }
}

// ---------------------------------------------------------------------------
// Verify: linear verifier logic against an abstract channel
// ---------------------------------------------------------------------------

impl<V> Verify<V> for CommittedSumcheck
where
    V: ReadProverMessage<Bytes>
        + ReadProverMessage<Fr>
        + SendVerifierMessage<u8>
        + ReadProverMessage<OpeningProof>,
{
    fn verify(ch: &mut V, instance: &Instance) -> VerificationResult<()> {
        let n = instance.n as usize;

        let root: Bytes = ch.read_prover_message()?;
        if root != instance.root {
            return Err(VerificationError);
        }

        // Bit-challenge sumcheck verification
        let mut claim = instance.claimed_sum;
        let mut idx: u32 = 0;

        for round in 0..n {
            let s0: Fr = ch.read_prover_message()?;
            let s1: Fr = ch.read_prover_message()?;
            if s0 + s1 != claim {
                return Err(VerificationError);
            }

            let x: u8 = ch.send_verifier_message();
            let b = x & 1;
            if b == 1 {
                idx |= 1u32 << round;
            }

            claim = if b == 0 { s0 } else { s1 };
        }

        // Read and verify opening proof
        let opening: OpeningProof = ch.read_prover_message()?;
        if opening.idx != idx || opening.value != claim {
            return Err(VerificationError);
        }

        let mut path_reader = opening.path_bytes.0.as_slice();
        let path = Path::<Sha256MerkleConfig>::deserialize_compressed(&mut path_reader)
            .map_err(|_| VerificationError)?;

        let (leaf_params, two_to_one_params) = Self::merkle_params();
        let leaf_bytes = Self::fr_to_leaf_bytes(&opening.value);

        let ok = path
            .verify(
                &leaf_params,
                &two_to_one_params,
                &root.0,
                leaf_bytes.as_slice(),
            )
            .unwrap();

        if !ok {
            return Err(VerificationError);
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Merkle tree helpers
// ---------------------------------------------------------------------------

impl CommittedSumcheck {
    fn fr_to_leaf_bytes(x: &Fr) -> Vec<u8> {
        canonical_to_bytes(x)
    }

    fn merkle_params() -> (LeafParam<Sha256MerkleConfig>, TwoToOneParam<Sha256MerkleConfig>) {
        ((), ())
    }

    fn build_merkle_tree(evals: &[Fr]) -> (MerkleTree<Sha256MerkleConfig>, Vec<u8>) {
        let leaves: Vec<Vec<u8>> = evals.iter().map(Self::fr_to_leaf_bytes).collect();
        let (leaf_params, two_to_one_params) = Self::merkle_params();

        let tree =
            MerkleTree::<Sha256MerkleConfig>::new(&leaf_params, &two_to_one_params, leaves).unwrap();

        let root = tree.root().to_vec();
        (tree, root)
    }
}

// ---------------------------------------------------------------------------
// Main: prove and verify via DSFS
// ---------------------------------------------------------------------------

fn main() {
    let n: u32 = 4;
    let size = 1usize << (n as usize);
    let mut rng = OsRng;
    let evals: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
    let claimed_sum = evals.iter().copied().sum::<Fr>();

    let (_tree, root) = CommittedSumcheck::build_merkle_tree(&evals);

    let instance = Instance {
        n,
        root: Bytes(root),
        claimed_sum,
    };

    let session = spongefish::session!("argus warmup: committed sumcheck");

    let narg_string = dsfs::prove::<CommittedSumcheck>(session, &instance, &evals);
    println!(
        "CommittedSumcheck proof bytes:\n{}",
        hex::encode(&narg_string)
    );

    dsfs::verify::<CommittedSumcheck>(session, &instance, &narg_string).expect("Invalid proof");
    println!("Verification succeeded");
}
