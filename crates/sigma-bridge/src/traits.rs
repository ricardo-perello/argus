//! Minimal Σ-protocol traits (API-compatible with σ-proofs for the Nizk transcript drivers).

use alloc::vec::Vec;

use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize};

/// RNG helper for scalar sampling (matches σ-proofs `ScalarRng`).
///
/// Implementations are typically provided via blanket impls in the consumer crate; for tests use
/// `rand::RngCore` with a small adapter.
pub trait ScalarRng {
    /// Draw cryptographic randomness (delegates to an inner RNG in practice).
    fn fill_bytes(&mut self, dest: &mut [u8]);
}

impl<T: rand_core::RngCore> ScalarRng for T {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        T::fill_bytes(self, dest);
    }
}

/// Three-message public-coin Σ-protocol (statement carried in `&self`, as in σ-proofs).
pub trait SigmaProtocol {
    type Commitment: Encoding<[u8]> + NargSerialize + NargDeserialize;
    type Challenge: Decoding<[u8]>;
    type Response: Encoding<[u8]> + NargSerialize + NargDeserialize;
    type ProverState;
    type Witness;

    fn prover_commit(
        &self,
        witness: &Self::Witness,
        rng: &mut impl ScalarRng,
    ) -> Result<(Vec<Self::Commitment>, Self::ProverState), SigmaBridgeError>;

    fn prover_response(
        &self,
        state: Self::ProverState,
        challenge: &Self::Challenge,
    ) -> Result<Vec<Self::Response>, SigmaBridgeError>;

    fn verifier(
        &self,
        commitment: &[Self::Commitment],
        challenge: &Self::Challenge,
        response: &[Self::Response],
    ) -> Result<(), ()>;

    fn commitment_len(&self) -> usize;
    fn response_len(&self) -> usize;
    fn protocol_identifier(&self) -> [u8; 64];
    fn instance_label(&self) -> impl AsRef<[u8]>;
}

/// Simulation hooks for compact proofs.
pub trait SigmaProtocolSimulator: SigmaProtocol {
    fn simulate_commitment(
        &self,
        challenge: &Self::Challenge,
        response: &[Self::Response],
    ) -> Result<Vec<Self::Commitment>, SigmaBridgeError>;
}

/// Errors from proving / serialization in this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigmaBridgeError {
    ProverFailed,
    VerificationFailed,
}

impl From<spongefish::VerificationError> for SigmaBridgeError {
    fn from(_: spongefish::VerificationError) -> Self {
        SigmaBridgeError::VerificationFailed
    }
}
