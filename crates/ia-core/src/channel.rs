//! Abstract prover/verifier channels (parameterized by the sponge alphabet
//! [`Unit`](ProverChannel::Unit)).

use crate::{Decoding, Deserialize, Encoding, NargSerialize, VerificationResult};

/// Prover-side channel: send prover messages and read verifier challenges.
///
/// [`Unit`](ProverChannel::Unit) is the sponge alphabet — `u8` for byte-oriented
/// hash functions, a field element for algebraic sponges in recursive settings.
/// It is an associated type rather than a generic parameter because a concrete
/// channel has exactly one alphabet (the one its sponge uses); a single channel
/// cannot meaningfully be both a `u8` and a field-element channel at once.
/// Byte-oriented protocols pin it with a `ProverChannel<Unit = u8>` bound.
///
/// Prover messages must implement [`NargSerialize`] so they can be written into
/// the non-interactive argument string by spongefish-backed channels.
pub trait ProverChannel {
    type Unit;
    fn send_prover_message<PM: Encoding<[Self::Unit]> + NargSerialize>(&mut self, msg: &PM);
    fn read_verifier_message<VM: Decoding<[Self::Unit]>>(&mut self) -> VM;
}

/// Verifier-side channel: read prover messages and derive verifier challenges.
///
/// See [`ProverChannel::Unit`] for why the alphabet is an associated type.
pub trait VerifierChannel {
    type Unit;
    fn read_prover_message<PM: Encoding<[Self::Unit]> + Deserialize>(
        &mut self,
    ) -> VerificationResult<PM>;
    fn send_verifier_message<VM: Decoding<[Self::Unit]>>(&mut self) -> VM;
}
