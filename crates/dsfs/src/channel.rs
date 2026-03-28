//! Sponge-backed `ProverChannel` / `VerifierChannel` adapters.

use ia_core::{Deserialize, ProverChannel, VerifierChannel};
use spongefish::{Decoding, Encoding, ProverState, VerifierState};

use crate::params::Keccak;

/// Wraps `spongefish::ProverState` as an ia-core `ProverChannel`.
pub struct SpongeProver {
    pub(crate) state: ProverState<Keccak>,
}

impl SpongeProver {
    pub fn new(state: ProverState<Keccak>) -> Self {
        Self { state }
    }

    pub fn narg_string(&self) -> &[u8] {
        self.state.narg_string()
    }
}

impl ProverChannel for SpongeProver {
    fn send_prover_message<PM: Encoding>(&mut self, msg: &PM) {
        self.state.prover_message(msg);
    }

    fn read_verifier_message<VM: Decoding>(&mut self) -> VM {
        self.state.verifier_message()
    }
}

/// Wraps `spongefish::VerifierState` as an ia-core `VerifierChannel`.
pub struct SpongeVerifier<'a> {
    pub(crate) state: VerifierState<'a, Keccak>,
}

impl<'a> SpongeVerifier<'a> {
    pub fn new(state: VerifierState<'a, Keccak>) -> Self {
        Self { state }
    }
}

impl VerifierChannel for SpongeVerifier<'_> {
    fn read_prover_message<PM: Encoding + Deserialize>(
        &mut self,
    ) -> ia_core::VerificationResult<PM> {
        self.state
            .prover_message()
            .map_err(|_| ia_core::VerificationError)
    }

    fn send_verifier_message<VM: Decoding>(&mut self) -> VM {
        self.state.verifier_message()
    }
}
