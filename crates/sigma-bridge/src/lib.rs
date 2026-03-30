//! Fiat–Shamir drivers matching σ-proofs [`Nizk`] **transcript layout** (batchable / compact).
//!
//! σ-proofs currently depends on spongefish **0.4** on crates.io; Argus pins spongefish **1.x** from
//! git. Because Cargo cannot unify those versions in one dependency graph, this crate defines a
//! minimal [`traits::SigmaProtocol`] surface (aligned with σ-proofs) that you can implement on your
//! protocol types—or `impl From` / newtype-wrap σ-proofs types when both crates share one spongefish
//! version (see project README / future σ-proofs bump).
//!
//! [`Nizk`]: https://github.com/sigma-rs/sigma-proofs/blob/main/src/fiat_shamir.rs

#![no_std]
extern crate alloc;

mod fiat_shamir;
pub mod session;
mod traits;

pub use fiat_shamir::{
    prove_batchable_sigma, prove_compact_sigma, verify_batchable_sigma, verify_compact_sigma,
};
pub use session::derive_session_id;
pub use traits::{ScalarRng, SigmaProtocol, SigmaProtocolSimulator};
