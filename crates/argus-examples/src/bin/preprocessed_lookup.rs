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
//! Compare to preprocessed_schnorr.rs and dleq.rs, where pk and vk are
//! the *same* data (the generator, or the public key) just held by both
//! sides. Here the indexer is doing real work — building a tree, and
//! routing each derived piece to the side that needs it.
//!
//! Run:  cargo run -p argus-examples --bin preprocessed_lookup

use blake3::{Hash, Hasher};
use spongefish_dsfs as dsfs;

use ia_core::{
    CommittedIndexBytes, NonInteractiveArgument, Preprocessed, ProverChannel, VerificationError,
    VerificationResult, VerifierChannel, VerifierKeyCommitment,
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

impl VerifierKeyCommitment for LookupVerifierKey {
    fn committed_index(&self) -> CommittedIndexBytes {
        let mut out = Vec::with_capacity(b"preprocessed-lookup:vk:v1".len() + 32 + 4);
        out.extend_from_slice(b"preprocessed-lookup:vk:v1");
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&self.n.to_le_bytes());
        CommittedIndexBytes::new(out)
    }
}

// ---------------------------------------------------------------------------
// The body — implements the indexed author trait
// ---------------------------------------------------------------------------

#[derive(Default)]
struct PreprocessedLookup;

ia_core::impl_preprocessing_argument! {
    impl PreprocessingInteractiveArgument for PreprocessedLookup {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            ia_core::pad_protocol_id(b"preprocessed-merkle-lookup")
        }

        /// Per-claim instance is (i, claimed_value).
        type Instance = (u32, u32);
        type Witness = ();
        type Index = Vec<u32>;
        type ProverKey = LookupProverKey;
        type VerifierKey = LookupVerifierKey;

        /// The real work: build the tree once, slice the result into a fat
        /// prover key (table + tree) and a thin verifier key (root + length).
        fn index(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
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

        fn prove<P: ProverChannel>(
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

        fn verify<V: VerifierChannel>(
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

    // Preprocessing: preprocessing_non_interactive_argument(body, sponge)
    // .prepare(&table) calls body.index(&table) once. Asymmetry visible in the
    // returned wrapper.
    let prepared =
        dsfs::preprocessing_non_interactive_argument(PreprocessedLookup, dsfs::Keccak::default())
            .prepare(&table);

    // Inspect the asymmetry via the `Preprocessed` capability.
    fn report<P: Preprocessed>(label: &str, p: &P)
    where
        P::ProverKey: core::fmt::Debug,
        P::VerifierKey: core::fmt::Debug,
    {
        println!("{label}:");
        println!("  Prover key:   {:?}", p.prover_key());
        println!("  Verifier key: {:?}", p.verifier_key());
        println!(
            "  Committed index: 0x{}\n",
            hex::encode(p.committed_index().as_bytes())
        );
    }
    report("Preprocessed wrapper (via `Preprocessed` trait)", &prepared);

    // Open three entries. Each proof is O(log n) hashes + the leaf value —
    // the verifier never reconstructs the table.
    for i in 0u32..3 {
        let y = table[i as usize];
        let proof = prepared.prove(&session, &(i, y), &());
        prepared.verify(&session, &(i, y), &proof).expect("verify");
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

    fn sample_table() -> Vec<u32> {
        (0..8u32).map(|i| 1000 + i).collect()
    }

    #[test]
    fn lookup_roundtrip() {
        let session = spongefish::session!("preprocessed lookup test");
        let table = sample_table();
        let prepared = dsfs::preprocessing_non_interactive_argument(
            PreprocessedLookup,
            dsfs::Keccak::default(),
        )
        .prepare(&table);

        for i in 0u32..table.len() as u32 {
            let y = table[i as usize];
            let proof = prepared.prove(&session, &(i, y), &());
            prepared
                .verify(&session, &(i, y), &proof)
                .expect("opening should verify");
        }
    }

    /// Wrong claimed value at a valid index — verifier rejects.
    #[test]
    fn lookup_rejects_wrong_value() {
        let session = spongefish::session!("preprocessed lookup test");
        let table = sample_table();
        let prepared = dsfs::preprocessing_non_interactive_argument(
            PreprocessedLookup,
            dsfs::Keccak::default(),
        )
        .prepare(&table);

        let proof = prepared.prove(&session, &(3, table[3]), &());
        // Same proof bytes, but claim a different value -> reject.
        let bogus = (3u32, table[3].wrapping_add(1));
        assert!(prepared.verify(&session, &bogus, &proof).is_err());
    }

    /// Two prepared wrappers built on different tables have different
    /// committed indices, so a proof under table A cannot be verified
    /// under table B even at the same (i, y).
    #[test]
    fn lookup_proof_does_not_cross_tables() {
        let session = spongefish::session!("preprocessed lookup test");
        let table_a = sample_table();
        let mut table_b = sample_table();
        table_b[0] = table_b[0].wrapping_add(1); // perturb one entry

        let prepared_a = dsfs::preprocessing_non_interactive_argument(
            PreprocessedLookup,
            dsfs::Keccak::default(),
        )
        .prepare(&table_a);
        let prepared_b = dsfs::preprocessing_non_interactive_argument(
            PreprocessedLookup,
            dsfs::Keccak::default(),
        )
        .prepare(&table_b);
        assert_ne!(prepared_a.committed_index(), prepared_b.committed_index());

        // Open table_a at index 5 (unperturbed in both).
        let proof = prepared_a.prove(&session, &(5, table_a[5]), &());
        assert!(
            prepared_b
                .verify(&session, &(5, table_a[5]), &proof)
                .is_err()
        );
    }

    /// Confirms the asymmetry: prover key holds the full table; verifier
    /// key holds 32 + 4 = 36 bytes regardless of table size.
    #[test]
    fn pk_grows_with_table_vk_stays_small() {
        fn vk_bytes<P: Preprocessed>(p: &P) -> usize
        where
            P::VerifierKey: AsVkBytes,
        {
            p.verifier_key().vk_byte_len()
        }

        trait AsVkBytes {
            fn vk_byte_len(&self) -> usize;
        }
        impl AsVkBytes for LookupVerifierKey {
            fn vk_byte_len(&self) -> usize {
                32 + 4
            }
        }

        let small = (0..2u32).collect::<Vec<_>>();
        let large = (0..1024u32).collect::<Vec<_>>();
        let p_small = dsfs::preprocessing_non_interactive_argument::<_, [u8; 64], _>(
            PreprocessedLookup,
            dsfs::Keccak::default(),
        )
        .prepare(&small);
        let p_large = dsfs::preprocessing_non_interactive_argument::<_, [u8; 64], _>(
            PreprocessedLookup,
            dsfs::Keccak::default(),
        )
        .prepare(&large);

        // PK scales with the table; VK does not.
        assert_eq!(p_small.prover_key().table.len(), 2);
        assert_eq!(p_large.prover_key().table.len(), 1024);
        assert_eq!(vk_bytes(&p_small), vk_bytes(&p_large));
    }
}
