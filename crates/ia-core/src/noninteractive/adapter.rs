//! Adapter viewing a NARG as a one-message interactive argument.

extern crate alloc;

use crate::{
    ArgumentCore, InteractiveArgument, NargProof, NonInteractiveArgument, ProtocolCore,
    ProverChannel, VerificationResult, VerifierChannel,
};

/// Adapter viewing a NARG as a one-message interactive argument.
///
/// The adapter fixes the NARG session because the `InteractiveArgument` API has
/// no separate session parameter. Its prover sends exactly one proof message;
/// its verifier reads that one message and performs the non-interactive check.
///
/// This is mostly a conceptual and testing adapter. It formalizes the useful
/// observation that a NARG can be embedded back into the IA interface as a
/// single prover-to-verifier message with no verifier challenges.
pub struct NargAsInteractiveArgument<N: NonInteractiveArgument> {
    /// The non-interactive argument being viewed interactively.
    pub narg: N,
    /// Fixed session used for every interactive execution of the adapter.
    pub session: N::Session,
}

impl<N: NonInteractiveArgument> NargAsInteractiveArgument<N> {
    /// Create a one-message IA adapter for `narg` under a fixed `session`.
    pub fn new(narg: N, session: N::Session) -> Self {
        Self { narg, session }
    }
}

impl<N> ProtocolCore for NargAsInteractiveArgument<N>
where
    N: NonInteractiveArgument,
{
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        self.narg.protocol_id()
    }
}

impl<N> ArgumentCore for NargAsInteractiveArgument<N>
where
    N: NonInteractiveArgument,
{
    type Instance = N::Instance;
    type Witness = N::Witness;
}

impl<N> InteractiveArgument for NargAsInteractiveArgument<N>
where
    N: NonInteractiveArgument,
{
    fn prove<P: ProverChannel>(
        &self,
        ch: &mut P,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) {
        let proof = self.narg.prove(&self.session, instance, witness);
        ch.send_prover_message(&proof);
    }

    fn verify<V: VerifierChannel>(
        &self,
        ch: &mut V,
        instance: &Self::Instance,
    ) -> VerificationResult<()> {
        let proof: NargProof = ch.read_prover_message()?;
        self.narg.verify(&self.session, instance, &proof)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;
    use crate::{Encoding, NargDeserialize, NargSerialize, VerificationError, pad_protocol_id};

    #[test]
    fn narg_proof_raw_access_roundtrips() {
        let proof = NargProof::from_bytes(vec![1, 2, 3]);
        assert_eq!(proof.as_bytes(), &[1, 2, 3]);
        assert_eq!(proof.clone().into_bytes(), vec![1, 2, 3]);
    }

    #[test]
    fn narg_proof_channel_encoding_is_length_delimited() {
        let proof = NargProof::from_bytes(vec![9, 8, 7]);
        let encoded = proof.encode();
        let encoded = encoded.as_ref();
        assert_eq!(&encoded[..8], &3u64.to_le_bytes());
        assert_eq!(&encoded[8..], &[9, 8, 7]);

        let mut cursor = encoded;
        let decoded = NargProof::deserialize_from_narg(&mut cursor).expect("valid proof");
        assert_eq!(decoded.as_bytes(), &[9, 8, 7]);
        assert!(cursor.is_empty());
    }

    #[derive(Default)]
    struct CountingProver {
        proof_bytes: Vec<u8>,
        verifier_reads: usize,
    }

    impl ProverChannel for CountingProver {
        fn send_prover_message<PM: Encoding<[u8]> + NargSerialize>(&mut self, msg: &PM) {
            msg.serialize_into_narg(&mut self.proof_bytes);
        }

        fn read_verifier_message<VM: crate::Decoding<[u8]>>(&mut self) -> VM {
            self.verifier_reads += 1;
            VM::decode(Default::default())
        }
    }

    struct CountingVerifier<'a> {
        cursor: &'a [u8],
        verifier_sends: usize,
    }

    impl VerifierChannel for CountingVerifier<'_> {
        fn read_prover_message<PM: Encoding<[u8]> + crate::Deserialize>(
            &mut self,
        ) -> VerificationResult<PM> {
            PM::deserialize(&mut self.cursor)
        }

        fn send_verifier_message<VM: crate::Decoding<[u8]>>(&mut self) -> VM {
            self.verifier_sends += 1;
            VM::decode(Default::default())
        }
    }

    struct DummyNarg;

    impl NonInteractiveArgument for DummyNarg {
        type Session = ();
        type Instance = u32;
        type Witness = u32;

        fn protocol_id(&self) -> impl AsRef<[u8]> {
            pad_protocol_id(b"dummy narg")
        }

        fn prove(
            &self,
            _session: &Self::Session,
            instance: &Self::Instance,
            witness: &Self::Witness,
        ) -> NargProof {
            NargProof::from_bytes(vec![*instance as u8, *witness as u8])
        }

        fn verify(
            &self,
            _session: &Self::Session,
            instance: &Self::Instance,
            proof: &NargProof,
        ) -> VerificationResult<()> {
            if proof.as_bytes().first().copied() == Some(*instance as u8) {
                Ok(())
            } else {
                Err(VerificationError)
            }
        }
    }

    #[test]
    fn narg_as_interactive_argument_is_one_prover_message_no_challenge() {
        let ia = NargAsInteractiveArgument::new(DummyNarg, ());
        let mut prover = CountingProver::default();
        ia.prove(&mut prover, &7, &11);
        assert_eq!(prover.verifier_reads, 0);
        assert!(!prover.proof_bytes.is_empty());

        let mut verifier = CountingVerifier {
            cursor: &prover.proof_bytes,
            verifier_sends: 0,
        };
        ia.verify(&mut verifier, &7).expect("valid NARG-as-IA");
        assert_eq!(verifier.verifier_sends, 0);
        assert!(verifier.cursor.is_empty());
    }
}
