//! Live interactive channel: prover and verifier communicate through mpsc channels.
//!
//! Provides `LiveProverChannel` and `LiveVerifierChannel` that implement
//! ia-core's `ProverChannel` and `VerifierChannel` traits over
//! `std::sync::mpsc`, enabling truly interactive protocol execution.

use std::sync::mpsc;

use ia_core::{Decoding, Encoding, NargDeserialize, VerificationError, VerificationResult};
use rand::rngs::OsRng;
use rand::RngCore;

// ---------------------------------------------------------------------------
// Live channel: prover side
// ---------------------------------------------------------------------------

pub struct LiveProverChannel {
    to_verifier: mpsc::Sender<Vec<u8>>,
    from_verifier: mpsc::Receiver<Vec<u8>>,
}

impl LiveProverChannel {
    pub fn new(
        to_verifier: mpsc::Sender<Vec<u8>>,
        from_verifier: mpsc::Receiver<Vec<u8>>,
    ) -> Self {
        Self {
            to_verifier,
            from_verifier,
        }
    }
}

impl ia_core::ProverChannel for LiveProverChannel {
    fn send_prover_message<M: Encoding>(&mut self, msg: &M) {
        let bytes = msg.encode();
        self.to_verifier.send(bytes.as_ref().to_vec()).unwrap();
    }

    fn read_verifier_message<C: Decoding>(&mut self) -> C {
        let bytes = self.from_verifier.recv().unwrap();
        let mut repr = C::Repr::default();
        repr.as_mut().copy_from_slice(&bytes);
        C::decode(repr)
    }
}

// ---------------------------------------------------------------------------
// Live channel: verifier side
// ---------------------------------------------------------------------------

pub struct LiveVerifierChannel {
    from_prover: mpsc::Receiver<Vec<u8>>,
    to_prover: mpsc::Sender<Vec<u8>>,
}

impl LiveVerifierChannel {
    pub fn new(
        from_prover: mpsc::Receiver<Vec<u8>>,
        to_prover: mpsc::Sender<Vec<u8>>,
    ) -> Self {
        Self {
            from_prover,
            to_prover,
        }
    }
}

impl ia_core::VerifierChannel for LiveVerifierChannel {
    fn read_prover_message<M: Encoding + NargDeserialize>(
        &mut self,
    ) -> VerificationResult<M> {
        let bytes = self.from_prover.recv().map_err(|_| VerificationError)?;
        let mut buf = bytes.as_slice();
        M::deserialize_from_narg(&mut buf).map_err(|_| VerificationError)
    }

    fn send_verifier_message<C: Decoding>(&mut self) -> C {
        let mut repr = C::Repr::default();
        OsRng.fill_bytes(repr.as_mut());
        self.to_prover.send(repr.as_mut().to_vec()).unwrap();
        C::decode(repr)
    }
}

/// Creates a linked pair of live channels: `(prover_channel, verifier_channel)`.
pub fn channel_pair() -> (LiveProverChannel, LiveVerifierChannel) {
    let (p_tx, p_rx) = mpsc::channel::<Vec<u8>>();
    let (v_tx, v_rx) = mpsc::channel::<Vec<u8>>();

    let prover = LiveProverChannel::new(p_tx, v_rx);
    let verifier = LiveVerifierChannel::new(p_rx, v_tx);
    (prover, verifier)
}
