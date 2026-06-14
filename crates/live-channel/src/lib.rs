//! Live interactive channel: prover and verifier communicate through mpsc channels.
//!
//! Provides `LiveProverChannel` and `LiveVerifierChannel` that implement
//! ia-core's `ProverChannel` and `VerifierChannel` traits over
//! `std::sync::mpsc`, enabling truly interactive protocol execution.
//!
//! # Error model
//!
//! The `ia-core` channel traits are infallible except for
//! [`VerifierChannel::read_prover_message`], which returns
//! [`VerificationResult`]. This crate therefore surfaces failures as follows:
//!
//! - **Verifier reading a prover message** (the one fallible operation): a
//!   disconnected prover, a malformed message, or trailing bytes are reported as
//!   [`VerificationError`] — never a panic. This is the security-relevant path
//!   (adversarial prover), so it must stay recoverable.
//! - **Every other operation** (prover/verifier sends, and the prover reading a
//!   challenge) is infallible by trait signature. The only failure modes are
//!   *environmental* — the peer thread dropped its end of the channel, or sent a
//!   wrong-length challenge — which leave no correct value to return and no error
//!   channel to use. These **panic** with a descriptive message (documented per
//!   method below). A fully fallible surface here would require changing the
//!   `ia-core` channel traits themselves.

use std::sync::mpsc;

use ia_core::{
    Decoding, Deserialize, Encoding, NargSerialize, VerificationError, VerificationResult,
};
use rand::RngCore;
use rand::rngs::OsRng;

// ---------------------------------------------------------------------------
// Live channel: prover side
// ---------------------------------------------------------------------------

pub struct LiveProverChannel {
    to_verifier: mpsc::Sender<Vec<u8>>,
    from_verifier: mpsc::Receiver<Vec<u8>>,
}

impl LiveProverChannel {
    pub fn new(to_verifier: mpsc::Sender<Vec<u8>>, from_verifier: mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            to_verifier,
            from_verifier,
        }
    }
}

impl ia_core::ProverChannel for LiveProverChannel {
    type Unit = u8;

    /// # Panics
    ///
    /// Panics if the verifier end of the channel has been dropped (the
    /// interactive session cannot continue and the trait signature is
    /// infallible).
    fn send_prover_message<M: Encoding + NargSerialize>(&mut self, msg: &M) {
        let bytes = msg.encode();
        self.to_verifier
            .send(bytes.as_ref().to_vec())
            .expect("live verifier disconnected while receiving a prover message");
    }

    /// # Panics
    ///
    /// Panics if the verifier end of the channel has been dropped before sending
    /// its challenge, or if the challenge bytes have the wrong encoded length for
    /// `C`. Both are unrecoverable for an infallible read.
    fn read_verifier_message<C: Decoding>(&mut self) -> C {
        let bytes = self
            .from_verifier
            .recv()
            .expect("live verifier disconnected before sending its challenge");
        let mut repr = C::Repr::default();
        assert_eq!(
            bytes.len(),
            repr.as_mut().len(),
            "live verifier challenge has the wrong encoded length"
        );
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
    pub fn new(from_prover: mpsc::Receiver<Vec<u8>>, to_prover: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            from_prover,
            to_prover,
        }
    }
}

impl ia_core::VerifierChannel for LiveVerifierChannel {
    type Unit = u8;

    /// Reads and decodes the next prover message.
    ///
    /// This is the only fallible channel operation: a disconnected prover, a
    /// message that fails to deserialize, or trailing bytes after a valid message
    /// all return [`VerificationError`] rather than panicking.
    fn read_prover_message<M: Encoding + Deserialize>(&mut self) -> VerificationResult<M> {
        let bytes = self.from_prover.recv().map_err(|_| VerificationError)?;
        let mut buf = bytes.as_slice();
        let message = M::deserialize(&mut buf)?;
        if buf.is_empty() {
            Ok(message)
        } else {
            Err(VerificationError)
        }
    }

    /// # Panics
    ///
    /// Panics if the prover end of the channel has been dropped before receiving
    /// the challenge (the trait signature is infallible).
    fn send_verifier_message<C: Decoding>(&mut self) -> C {
        let mut repr = C::Repr::default();
        OsRng.fill_bytes(repr.as_mut());
        self.to_prover
            .send(repr.as_mut().to_vec())
            .expect("live prover disconnected before receiving the verifier challenge");
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

#[cfg(test)]
mod tests {
    use std::thread;

    use ia_core::{ProverChannel, VerifierChannel};

    use super::channel_pair;

    #[test]
    fn supports_multiple_interactive_rounds() {
        let (mut prover, mut verifier) = channel_pair();

        let prover_thread = thread::spawn(move || {
            prover.send_prover_message(&11u32);
            let first: [u8; 32] = prover.read_verifier_message();
            prover.send_prover_message(&29u32);
            let second: [u8; 32] = prover.read_verifier_message();
            (first, second)
        });

        assert_eq!(verifier.read_prover_message::<u32>().unwrap(), 11);
        let first: [u8; 32] = verifier.send_verifier_message();
        assert_eq!(verifier.read_prover_message::<u32>().unwrap(), 29);
        let second: [u8; 32] = verifier.send_verifier_message();

        assert_eq!(prover_thread.join().unwrap(), (first, second));
    }

    #[test]
    fn verifier_reports_a_disconnected_prover() {
        let (prover, mut verifier) = channel_pair();
        drop(prover);

        assert!(verifier.read_prover_message::<u32>().is_err());
    }
}
