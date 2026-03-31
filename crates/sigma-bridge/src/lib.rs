//! Sigma-protocol → Interactive-Argument bridge via DSFS.
//!
//! Wraps any [`SigmaProtocol`] and drives it through `ia-core`'s `ProverChannel` / `VerifierChannel`
//! backed by a `dsfs::SpongeProver` / `SpongeVerifier`. The proof is the full spongefish NARG
//! string (commitments + responses serialized via `prover_message`, not `public_message`).

#![no_std]
extern crate alloc;

mod fiat_shamir;
pub mod ia;
pub mod session;

pub use fiat_shamir::{prove, prove_with_protocol_domain, verify, verify_with_protocol_domain};
pub use ia::SigmaIA;
pub use session::derive_session_id;

pub use sigma_proofs::traits::{ScalarRng, SigmaProtocol};
