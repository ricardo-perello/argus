//! DSFS compiler: Duplex-Sponge Fiat-Shamir transformation (Construction 4.3, Chiesa-Orru 2025).
//!
//! Wraps spongefish's `ProverState` and `VerifierState` behind ia-core's
//! abstract channel traits. This is the **only** layer that touches the sponge.
//!
//! Supports both interactive arguments (`prove`/`verify`) and interactive
//! oracle reductions (`prove_reduction`/`verify_reduction`).
//!
//! Submodules: [`params`](crate::params), [`narg_security`](crate::narg_security),
//! [`channel`](crate::channel), [`compile`](crate::compile).
#![no_std]
extern crate alloc;

mod channel;
mod compile;
mod narg_security;
mod params;

pub use channel::{SpongeProver, SpongeVerifier};
pub use compile::{
    prove, prove_reduction, prove_reduction_with_salt, prove_with_salt, verify, verify_reduction,
    verify_reduction_with_salt, verify_with_salt,
};
pub use narg_security::{reduction_security, security, NargSecurity};
pub use params::{
    DuplexSpongeParamsExt, Keccak, SpongeParams, STD_SPONGE_PARAMS,
};
