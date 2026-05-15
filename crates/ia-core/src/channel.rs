//! Abstract prover/verifier channels (generic over sponge alphabet unit `U`).

use crate::{Decoding, Deserialize, Encoding, NargSerialize, VerificationResult};

/// Prover-side channel: send prover messages and read verifier challenges.
///
/// Generic over the sponge unit type `U` (default `u8` for byte-oriented
/// hash functions; a field element for algebraic sponges in recursive
/// settings).
///
/// Prover messages must implement [`NargSerialize`] so they can be written into
/// the non-interactive argument string by spongefish-backed channels.
pub trait ProverChannel<U = u8> {
    fn send_prover_message<PM: Encoding<[U]> + NargSerialize>(&mut self, msg: &PM);
    fn read_verifier_message<VM: Decoding<[U]>>(&mut self) -> VM;
}

/// Verifier-side channel: read prover messages and derive verifier challenges.
pub trait VerifierChannel<U = u8> {
    fn read_prover_message<PM: Encoding<[U]> + Deserialize>(&mut self) -> VerificationResult<PM>;
    fn send_verifier_message<VM: Decoding<[U]>>(&mut self) -> VM;
}
