//! Committed Boolean Sumcheck (warmup IARG-ish protocol)
//!
//! Tools:
//! - spongefish: DSFS transcript (absorb prover msgs, squeeze verifier challenges)
//! - ark-crypto-primitives: Merkle tree commitment + opening + verification
//!
//! Protocol idea:
//! - Prover commits to the full evaluation table evals via a Merkle root.
//! - Run “sumcheck” with *bit* challenges b_i ∈ {0,1} (derived via spongefish).
//!   This collapses the claim to a single table entry evals[idx].
//! - Prover opens the Merkle tree at idx and verifier checks opening + value == claim.

use ark_curve25519::Fr;
use ark_ff::Zero;
use ark_std::UniformRand;
use rand::rngs::OsRng;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use spongefish::{protocol_id, DomainSeparator, Encoding, ProverState, VerifierState};
use spongefish::{VerificationError, VerificationResult};

use ark_crypto_primitives::crh::sha256::Sha256;
use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};
use ark_crypto_primitives::merkle_tree::{Config, DigestConverter, MerkleTree, Path};

struct CommittedSumcheck;

/// Length-delimited byte blob for transcript messages.
#[derive(Clone, Default, PartialEq, Eq)]
struct Blob(Vec<u8>);

impl Encoding for Blob {
    fn encode(&self) -> impl AsRef<[u8]> {
        let mut out = Vec::with_capacity(4 + self.0.len());
        out.extend_from_slice(&(self.0.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.0);
        out
    }
}

impl spongefish::NargDeserialize for Blob {
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        if buf.len() < 4 {
            return Err(VerificationError);
        }
        let (len_bytes, rest) = buf.split_at(4);
        let len = u32::from_le_bytes(len_bytes.try_into().map_err(|_| VerificationError)?) as usize;
        if rest.len() < len {
            return Err(VerificationError);
        }
        let (payload, tail) = rest.split_at(len);
        *buf = tail;
        Ok(Self(payload.to_vec()))
    }
}

/// Public instance: root commitment + claimed sum.
#[derive(Clone, Encoding)]
struct Instance {
    /// Number of variables n for f : {0,1}^n -> F.
    n: u32,
    /// Merkle root committing to the evaluation table.
    root: Blob,
    /// Claimed sum S = Σ_{x∈{0,1}^n} f(x).
    claimed_sum: Fr,
}

/// Opening proof in the NARG string.
/// We keep the Merkle path as bytes to avoid wrestling with Encoding bounds.
#[derive(Clone, Encoding, spongefish::NargDeserialize)]
struct OpeningProof {
    idx: u32,
    value: Fr,
    path_bytes: Blob,
}

/// Merkle configuration for SHA-256.
///
/// - Leaves are raw bytes (`[u8]`) representing serialized field elements.
/// - Digests are `Vec<u8>` (32 bytes for SHA-256).
#[derive(Clone)]
pub struct Sha256MerkleConfig;

/// Convert a leaf digest (Vec<u8>) into bytes for inner hashing.
/// We want the raw digest bytes, not “canonical serialization of Vec<u8>”.
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

impl CommittedSumcheck {
    pub fn protocol_id() -> [u8; 64] {
        protocol_id(core::format_args!("committed sumcheck (bit challenges, sha256 merkle)"))
    }

    fn fr_to_leaf_bytes(x: &Fr) -> Vec<u8> {
        let mut v = Vec::new();
        x.serialize_compressed(&mut v).unwrap();
        v
    }

    fn build_merkle_tree(evals: &[Fr]) -> (Vec<Vec<u8>>, MerkleTree<Sha256MerkleConfig>, Vec<u8>) {
        // Leaf bytes for the Merkle tree.
        let leaves: Vec<Vec<u8>> = evals.iter().map(Self::fr_to_leaf_bytes).collect();

        // For Sha256 CRH schemes in ark-crypto-primitives, Parameters are `()`.
        // Still, we obtain them via setup() for consistency.
        let mut rng = OsRng;
        let leaf_params = <Sha256 as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_params = <Sha256 as TwoToOneCRHScheme>::setup(&mut rng).unwrap();

        let tree =
            MerkleTree::<Sha256MerkleConfig>::new(&leaf_params, &two_to_one_params, leaves.clone())
                .unwrap();

        let root = tree.root().to_vec();
        (leaves, tree, root)
    }

    fn squeeze_bit_from_prover(ps: &mut ProverState) -> u8 {
        let x: u8 = ps.verifier_message();
        x & 1
    }

    fn squeeze_bit_from_verifier(vs: &mut VerifierState) -> u8 {
        let x: u8 = vs.verifier_message();
        x & 1
    }

    /// Prover: commits to evals (root), runs bit-challenge sumcheck, then opens one leaf.
    pub fn prove<'a>(
        prover_state: &'a mut ProverState,
        instance: &Instance,
        evals: &[Fr], // witness table
    ) -> &'a [u8] {
        let n = instance.n as usize;
        let expected = 1usize << n;
        assert_eq!(evals.len(), expected, "evals must have length 2^n");

        // Build Merkle commitment from witness.
        let (_leaves, tree, root) = Self::build_merkle_tree(evals);
        assert_eq!(
            root.as_slice(),
            instance.root.0.as_slice(),
            "instance.root must match witness evals"
        );

        // Commit phase: send root as a prover message and absorb it into transcript.
        prover_state.prover_message(&instance.root);

        // Sumcheck with bit challenges.
        let mut table = evals.to_vec();
        let mut claim = instance.claimed_sum;
        let mut idx: u32 = 0;

        for round in 0..n {
            // s0,s1 sums over pairs (even/odd) like your original convention (x1 is LSB).
            let mut s0 = Fr::zero();
            let mut s1 = Fr::zero();
            for pair in table.chunks_exact(2) {
                s0 += pair[0];
                s1 += pair[1];
            }

            // Prover message: (s0,s1)
            prover_state.prover_messages(&[s0, s1]);

            // Verifier bit challenge derived from spongefish transcript
            let b = Self::squeeze_bit_from_prover(prover_state);
            if b == 1 {
                idx |= 1u32 << round;
            }

            // Update claim = s_b
            claim = if b == 0 { s0 } else { s1 };

            // Fold table by selecting consistent half for each pair
            let mut next = Vec::with_capacity(table.len() / 2);
            for pair in table.chunks_exact(2) {
                next.push(if b == 0 { pair[0] } else { pair[1] });
            }
            table = next;
        }

        debug_assert_eq!(table.len(), 1);
        debug_assert_eq!(table[0], claim);

        // Opening phase: open the committed table at idx.
        let value = evals[idx as usize];
        let path: Path<Sha256MerkleConfig> = tree.generate_proof(idx as usize).unwrap();

        // Serialize path as bytes for the NARG.
        let mut path_bytes = Vec::new();
        path.serialize_compressed(&mut path_bytes).unwrap();

        let opening = OpeningProof {
            idx,
            value,
            path_bytes: Blob(path_bytes),
        };
        prover_state.prover_message(&opening);

        prover_state.narg_string()
    }

    /// Verifier: reads root, runs checks with squeezed bit challenges, verifies Merkle opening.
    pub fn verify(
        mut verifier_state: VerifierState,
        instance: &Instance,
    ) -> VerificationResult<()> {
        let n = instance.n as usize;

        // Read commitment root from proof and compare to instance.root
        let root = verifier_state.prover_message::<Blob>()?;
        if root != instance.root {
            return Err(VerificationError);
        }

        // Bit-challenge sumcheck verification
        let mut claim = instance.claimed_sum;
        let mut idx: u32 = 0;

        for round in 0..n {
            let [s0, s1] = verifier_state.prover_messages::<Fr, 2>()?;
            if s0 + s1 != claim {
                return Err(VerificationError);
            }

            let b = Self::squeeze_bit_from_verifier(&mut verifier_state);
            if b == 1 {
                idx |= 1u32 << round;
            }

            claim = if b == 0 { s0 } else { s1 };
        }

        // Read opening proof
        let opening = verifier_state.prover_message::<OpeningProof>()?;
        if opening.idx != idx {
            return Err(VerificationError);
        }
        if opening.value != claim {
            return Err(VerificationError);
        }

        // Verify Merkle membership proof
        let path =
            Path::<Sha256MerkleConfig>::deserialize_compressed(opening.path_bytes.0.as_slice())
                .unwrap();

        // Recreate params for SHA-256 (they are `()` under the hood, but we follow the API)
        let mut rng = OsRng;
        let leaf_params = <Sha256 as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_params = <Sha256 as TwoToOneCRHScheme>::setup(&mut rng).unwrap();

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

        verifier_state.check_eof()?;
        Ok(())
    }
}

fn main() {
    // Witness table
    let n: u32 = 4;
    let size = 1usize << (n as usize);
    let mut rng = OsRng;
    let evals = (0..size).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
    let claimed_sum = evals.iter().copied().sum::<Fr>();

    // Commit to evals via Merkle
    let (_leaves, _tree, root) = CommittedSumcheck::build_merkle_tree(&evals);

    // Public instance
    let instance = Instance {
        n,
        root: Blob(root),
        claimed_sum,
    };

    // Spongefish domain separation: protocol + session + instance
    let domain_separator = DomainSeparator::new(CommittedSumcheck::protocol_id())
        .session(spongefish::session!("argus warmup: committed sumcheck"))
        .instance(&instance);

    // Prove
    let mut prover_state = domain_separator.std_prover();
    let narg_string = CommittedSumcheck::prove(&mut prover_state, &instance, &evals);

    println!(
        "CommittedSumcheck proof bytes:\n{}",
        hex::encode(narg_string)
    );

    // Verify
    let verifier_state = domain_separator.std_verifier(narg_string);
    CommittedSumcheck::verify(verifier_state, &instance).expect("Invalid proof");
}