//! Placeholder for cross-crate golden vectors against σ-proofs `Nizk`.
//!
//! **Status:** `sigma-proofs` on crates.io uses spongefish 0.4; this workspace uses spongefish 1.x from git.
//! A single test binary cannot depend on both. When versions align (or via a small separate lockfile / forked
//! σ-proofs), add tests that:
//! - call `Nizk::prove_batchable` / `verify_batchable` with `StdHash`,
//! - call `sigma_bridge::prove_batchable_sigma` / `verify_batchable_sigma` with the same `P`, witness, and RNG seed,
//! - assert `proof == expected` byte-for-word.
//!
//! The same applies to compact proofs.

#[test]
fn golden_vectors_documented() {
    // Intentionally empty: see module docs.
}
