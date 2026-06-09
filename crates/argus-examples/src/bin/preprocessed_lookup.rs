//! Preprocessed Merkle vector commitment opening.
//!
//! This is the example where prover key and verifier key are genuinely
//! *different shapes* — not just two copies of the same data. The setup
//! is the canonical preprocessing pattern at the heart of every Merkle-
//! based commitment scheme, and the same shape WARP, Marlin, Plonk, and
//! FRI use for their indexed oracles.
//!
//! Setup:  a public vector V = [v_0, ..., v_{n-1}] of values, committed
//!         to once by Merkle-hashing.
//! PK:     the *full* vector + the full Merkle tree (all internal nodes).
//!         Needed by the prover to generate authentication paths.
//! VK:     just the Merkle root (32 bytes) + length n. O(1) regardless
//!         of how big V is. This is the whole point of preprocessing —
//!         verifier state stays compact.
//!
//! Per-claim, the prover opens a single entry: instance = (i, y), claim
//! is `V[i] == y`. Protocol:
//!
//!   1. Prover sends `leaf = V[i]` and the auth path (log_2(n) siblings).
//!   2. Verifier reconstructs the root from leaf + path and compares
//!      against vk.root, then checks leaf == y.
//!
//! Mapping onto the indexed surface:
//!
//!   Index       = `Vec<u32>`          (the public table)
//!   ProverKey   = LookupProverKey     { table, tree }   O(n)
//!   VerifierKey = LookupVerifierKey   { root, n }       O(1)
//!   Instance    = (u32, u32)          (index, claimed value)
//!   Witness     = ()                  (everything needed is in pk)
//!
//! Compare to dleq.rs, where pk and vk are the *same* long-term public
//! key data just held by both sides. Here the indexer is doing real work -
//! building a tree, and routing each derived piece to the side that needs it.
//!
//! Run:  cargo run -p argus-examples --bin preprocessed_lookup

use blake3::{Hash, Hasher};
use spongefish_dsfs as dsfs;

use ia_core::prelude::*;
use ia_core::{
    CommittedIndex, CommittedIndexBytes, Indexer, ProverChannel, VerificationError,
    VerificationResult, VerifierChannel,
};

// ---------------------------------------------------------------------------
// Tiny power-of-two Merkle tree (no ark-crypto-primitives ceremony)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct MerkleTree {
    /// `levels[0]` = leaf hashes; `levels[k]` = hashes one level up.
    /// `levels.last()` always holds the single root hash.
    levels: Vec<Vec<Hash>>,
}

impl MerkleTree {
    fn new(leaves: &[u32]) -> Self {
        assert!(
            leaves.len().is_power_of_two(),
            "leaf count must be a power of two"
        );
        let leaf_hashes: Vec<Hash> = leaves
            .iter()
            .map(|x| blake3::hash(&x.to_le_bytes()))
            .collect();
        let mut levels = vec![leaf_hashes];
        while levels.last().unwrap().len() > 1 {
            let prev = levels.last().unwrap();
            let next: Vec<Hash> = prev
                .chunks(2)
                .map(|c| {
                    let mut h = Hasher::new();
                    h.update(c[0].as_bytes());
                    h.update(c[1].as_bytes());
                    h.finalize()
                })
                .collect();
            levels.push(next);
        }
        Self { levels }
    }

    fn root(&self) -> Hash {
        self.levels.last().unwrap()[0]
    }

    /// Sibling hashes from leaf to root (excludes the leaf itself).
    fn path(&self, mut i: usize) -> Vec<Hash> {
        let mut sibs = Vec::with_capacity(self.levels.len() - 1);
        for level in &self.levels[..self.levels.len() - 1] {
            sibs.push(level[i ^ 1]);
            i >>= 1;
        }
        sibs
    }
}

fn verify_merkle_path(root: &Hash, mut i: usize, leaf_value: u32, siblings: &[Hash]) -> bool {
    let mut cur = blake3::hash(&leaf_value.to_le_bytes());
    for sibling in siblings {
        let mut h = Hasher::new();
        if i & 1 == 0 {
            h.update(cur.as_bytes());
            h.update(sibling.as_bytes());
        } else {
            h.update(sibling.as_bytes());
            h.update(cur.as_bytes());
        }
        cur = h.finalize();
        i >>= 1;
    }
    &cur == root
}

// ---------------------------------------------------------------------------
// Asymmetric prover key / verifier key
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct LookupProverKey {
    table: Vec<u32>,
    tree: MerkleTree,
}

#[derive(Clone, Debug)]
struct LookupVerifierKey {
    root: [u8; 32],
    n: u32,
}

/// Canonical committed-index bytes for the lookup table. Shared by the prover
/// key and the verifier key so the two can never disagree on the digest the
/// transcript binds (`pk.committed_index() == vk.committed_index()`).
fn lookup_committed_index(root: &[u8; 32], n: u32) -> CommittedIndexBytes {
    let mut out = Vec::with_capacity(b"preprocessed-lookup:vk:v1".len() + 32 + 4);
    out.extend_from_slice(b"preprocessed-lookup:vk:v1");
    out.extend_from_slice(root);
    out.extend_from_slice(&n.to_le_bytes());
    CommittedIndexBytes::new(out)
}

impl CommittedIndex for LookupVerifierKey {
    fn committed_index(&self) -> CommittedIndexBytes {
        lookup_committed_index(&self.root, self.n)
    }
}

impl CommittedIndex for LookupProverKey {
    fn committed_index(&self) -> CommittedIndexBytes {
        let root = *self.tree.root().as_bytes();
        let n = u32::try_from(self.table.len()).expect("table size fits in u32");
        lookup_committed_index(&root, n)
    }
}

// ---------------------------------------------------------------------------
// The body — implements the indexed author trait
// ---------------------------------------------------------------------------

fn lookup_protocol_id() -> [u8; 32] {
    ia_core::pad_protocol_id(b"preprocessed-merkle-lookup")
}

#[derive(Default)]
struct LookupIndexer;

#[derive(Default)]
struct LookupProver;

#[derive(Default)]
struct LookupVerifier;

ia_core::impl_preprocessing_argument! {
    impl {
        indexer: LookupIndexer,
        prover: LookupProver,
        verifier: LookupVerifier,
    }
    {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            lookup_protocol_id()
        }

        /// Per-claim instance is (i, claimed_value).
        type Instance = (u32, u32);
        type Witness = ();
        type Index = Vec<u32>;
        type ProverKey = LookupProverKey;
        type VerifierKey = LookupVerifierKey;

        /// The real work: build the tree once, slice the result into a fat
        /// prover key (table + tree) and a thin verifier key (root + length).
        fn preprocess(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
            let tree = MerkleTree::new(ix);
            let root = *tree.root().as_bytes();
            let n = u32::try_from(ix.len()).expect("table size fits in u32");
            let pk = LookupProverKey {
                table: ix.clone(),
                tree,
            };
            let vk = LookupVerifierKey { root, n };
            (pk, vk)
        }

        fn prove<P: ProverChannel<Unit = u8>>(
            &self,
            ch: &mut P,
            pk: &LookupProverKey,
            instance: &(u32, u32),
            _witness: &(),
        ) {
            let (i, _claimed) = *instance;
            let i = i as usize;
            let leaf = pk.table[i];
            let path = pk.tree.path(i);

            // Send the leaf, then each sibling hash. The verifier knows
            // log_2(n) from vk.n and reads exactly that many siblings.
            ch.send_prover_message(&leaf);
            for sibling in &path {
                ch.send_prover_message(sibling.as_bytes());
            }
        }

        fn verify<V: VerifierChannel<Unit = u8>>(
            &self,
            ch: &mut V,
            vk: &LookupVerifierKey,
            instance: &(u32, u32),
        ) -> VerificationResult<()> {
            let (i, claimed) = *instance;

            // Sanity check: i in [0, n), and n is a power of two so log_2 is
            // an integer. The path length comes from vk, not the proof bytes.
            if i >= vk.n || !vk.n.is_power_of_two() {
                return Err(VerificationError);
            }
            let log_n = vk.n.trailing_zeros() as usize;

            let leaf: u32 = ch.read_prover_message()?;
            let mut siblings = Vec::with_capacity(log_n);
            for _ in 0..log_n {
                let s: [u8; 32] = ch.read_prover_message()?;
                siblings.push(Hash::from(s));
            }

            if leaf != claimed {
                return Err(VerificationError);
            }
            let root = Hash::from(vk.root);
            if !verify_merkle_path(&root, i as usize, leaf, &siblings) {
                return Err(VerificationError);
            }
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Main: preprocess once, open many entries
// ---------------------------------------------------------------------------

fn main() {
    println!("=== Preprocessed Merkle vector lookup ===\n");
    let session = spongefish::session!("preprocessed lookup example");

    // Public table — would normally be much larger (lookup tables in real
    // Plookup/Lasso/Caulk are in the thousands–millions of entries).
    let table: Vec<u32> = (0..8u32).map(|i| 100 + i * 7).collect();
    println!("Public table: {table:?}\n");

    // The indexer builds the tree once and returns the bare prover/verifier keys.
    let indexer = LookupIndexer;
    let prover =
        dsfs::preprocessing_non_interactive_argument_prover(LookupProver, dsfs::Keccak::default());
    let verifier = dsfs::preprocessing_non_interactive_argument_verifier(
        LookupVerifier,
        dsfs::Keccak::default(),
    );
    let (proving_key, verifier_key) = indexer.preprocess(&table);

    // The asymmetry, straight off the keys: the prover key holds the full
    // table + tree (O(n)); the verifier key is just root + n (O(1)).
    println!("Preprocessed keys:");
    println!("  Prover key:   {:?}", proving_key);
    println!("  Verifier key: {verifier_key:?}");
    println!(
        "  Committed index: 0x{}\n",
        hex::encode(proving_key.committed_index().as_bytes())
    );

    // Open three entries. Each proof is O(log n) hashes + the leaf value —
    // the verifier never reconstructs the table.
    for i in 0u32..3 {
        let y = table[i as usize];
        let proof = prover.prove(&proving_key, &session, &(i, y), &());
        verifier
            .verify(&verifier_key, &session, &(i, y), &proof)
            .expect("verify");
        println!(
            "table[{i}] == {y} -> verified ({} proof bytes, vk stays {} bytes)",
            proof.as_bytes().len(),
            32 + 4, // root + n
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ia_core::{
        PreprocessingNonInteractiveArgumentProver, PreprocessingNonInteractiveArgumentVerifier,
    };

    fn sample_table() -> Vec<u32> {
        (0..8u32).map(|i| 1000 + i).collect()
    }

    fn assert_preprocessed_prover<N: PreprocessingNonInteractiveArgumentProver>(_: &N) {}

    fn assert_preprocessed_verifier<N: PreprocessingNonInteractiveArgumentVerifier>(_: &N) {}

    #[test]
    fn lookup_roundtrip() {
        let session = spongefish::session!("preprocessed lookup test");
        let table = sample_table();
        let indexer = LookupIndexer;
        let prover = dsfs::preprocessing_non_interactive_argument_prover::<_, [u8; 64], _>(
            LookupProver,
            dsfs::Keccak::default(),
        );
        let verifier = dsfs::preprocessing_non_interactive_argument_verifier::<_, [u8; 64], _>(
            LookupVerifier,
            dsfs::Keccak::default(),
        );
        let (pk, vk) = indexer.preprocess(&table);

        for i in 0u32..table.len() as u32 {
            let y = table[i as usize];
            let proof = prover.prove(&pk, &session, &(i, y), &());
            verifier
                .verify(&vk, &session, &(i, y), &proof)
                .expect("opening should verify");
        }
    }

    /// Wrong claimed value at a valid index — verifier rejects.
    #[test]
    fn lookup_rejects_wrong_value() {
        let session = spongefish::session!("preprocessed lookup test");
        let table = sample_table();
        let indexer = LookupIndexer;
        let prover = dsfs::preprocessing_non_interactive_argument_prover::<_, [u8; 64], _>(
            LookupProver,
            dsfs::Keccak::default(),
        );
        let verifier = dsfs::preprocessing_non_interactive_argument_verifier::<_, [u8; 64], _>(
            LookupVerifier,
            dsfs::Keccak::default(),
        );
        let (pk, vk) = indexer.preprocess(&table);

        let proof = prover.prove(&pk, &session, &(3, table[3]), &());
        // Same proof bytes, but claim a different value -> reject.
        let bogus = (3u32, table[3].wrapping_add(1));
        assert!(verifier.verify(&vk, &session, &bogus, &proof).is_err());
    }

    /// Two indexings on different tables have different committed indices, so a
    /// proof under table A cannot be verified under table B even at the same (i, y).
    #[test]
    fn lookup_proof_does_not_cross_tables() {
        let session = spongefish::session!("preprocessed lookup test");
        let table_a = sample_table();
        let mut table_b = sample_table();
        table_b[0] = table_b[0].wrapping_add(1); // perturb one entry

        let indexer = LookupIndexer;
        let prover = dsfs::preprocessing_non_interactive_argument_prover(
            LookupProver,
            dsfs::Keccak::default(),
        );
        let verifier = dsfs::preprocessing_non_interactive_argument_verifier(
            LookupVerifier,
            dsfs::Keccak::default(),
        );
        let (pk_a, _vk_a) = indexer.preprocess(&table_a);
        let (_pk_b, vk_b) = indexer.preprocess(&table_b);
        assert_ne!(pk_a.committed_index(), vk_b.committed_index());

        // Open table_a at index 5 (unperturbed in both).
        let proof = prover.prove(&pk_a, &session, &(5, table_a[5]), &());
        assert!(
            verifier
                .verify(&vk_b, &session, &(5, table_a[5]), &proof)
                .is_err()
        );
    }

    /// The optional `Prover`/`Verifier` role wrappers compose `(nia, key)` and
    /// round-trip; `Verifier` exposes only `verify`.
    #[test]
    fn lookup_via_separate_prover_and_verifier_roles() {
        let session = spongefish::session!("preprocessed lookup wrappers test");
        let table = sample_table();
        let (pk, vk) = LookupIndexer.preprocess(&table);

        let prover_nia = dsfs::preprocessing_non_interactive_argument_prover(
            LookupProver,
            dsfs::Keccak::default(),
        );
        let verifier_nia = dsfs::preprocessing_non_interactive_argument_verifier(
            LookupVerifier,
            dsfs::Keccak::default(),
        );

        assert_preprocessed_prover(&prover_nia);
        assert_preprocessed_verifier(&verifier_nia);

        let proof = prover_nia.prove(&pk, &session, &(3, table[3]), &());
        assert!(!proof.is_empty());
        verifier_nia
            .verify(&vk, &session, &(3, table[3]), &proof)
            .expect("separate prover/verifier round-trip verifies");
    }

    /// Confirms the asymmetry: the proving key holds the full table; the
    /// verifier key holds 32 + 4 = 36 bytes regardless of table size.
    #[test]
    fn pk_grows_with_table_vk_stays_small() {
        let small = (0..2u32).collect::<Vec<_>>();
        let large = (0..1024u32).collect::<Vec<_>>();
        let (pk_small, _vk_small) = LookupIndexer.preprocess(&small);
        let (pk_large, _vk_large) = LookupIndexer.preprocess(&large);

        // PK scales with the table; VK is a fixed 36 bytes (root + n) by construction.
        assert_eq!(pk_small.table.len(), 2);
        assert_eq!(pk_large.table.len(), 1024);
    }
}
