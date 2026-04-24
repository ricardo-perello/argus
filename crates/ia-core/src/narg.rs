//! Non-interactive argument abstractions.

extern crate alloc;

use alloc::vec::Vec;

use crate::{
    Deserialize, Encoding, InteractiveArgument, NargDeserialize, ProverChannel, VerificationError,
    VerificationResult, VerifierChannel,
};

/// Opaque byte artifact produced by a non-interactive argument compiler.
///
/// `NargProof` deliberately carries no transcript semantics: sponge choice,
/// salt policy, domain separation, and proof layout are owned by the compiler
/// that produced the bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NargProof(Vec<u8>);

impl NargProof {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[u8]> for NargProof {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Encoding<[u8]> for NargProof {
    fn encode(&self) -> impl AsRef<[u8]> {
        let len = u64::try_from(self.0.len()).expect("NARG proof length exceeds u64");
        let mut out = Vec::with_capacity(8 + self.0.len());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&self.0);
        out
    }
}

impl NargDeserialize for NargProof {
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        let mut rest = *buf;
        let len_bytes: [u8; 8] = NargDeserialize::deserialize_from_narg(&mut rest)?;
        let len = u64::from_le_bytes(len_bytes);
        let len = usize::try_from(len).map_err(|_| VerificationError)?;
        if rest.len() < len {
            return Err(VerificationError);
        }
        let (proof, tail) = rest.split_at(len);
        *buf = tail;
        Ok(Self(proof.to_vec()))
    }
}

/// Abstract non-interactive argument.
pub trait NonInteractiveArgument {
    type Session;
    type Instance;
    type Witness;
    type Proof;

    fn protocol_id(&self) -> impl AsRef<[u8]>;

    fn prove(
        &self,
        session: &Self::Session,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> Self::Proof;

    fn verify(
        &self,
        session: &Self::Session,
        instance: &Self::Instance,
        proof: &Self::Proof,
    ) -> VerificationResult<()>;
}

/// Abstract non-interactive reduction.
pub trait NonInteractiveReduction {
    type Session;
    type SourceInstance;
    type TargetInstance;
    type SourceWitness;
    type TargetWitness;
    type Proof;

    fn protocol_id(&self) -> impl AsRef<[u8]>;

    fn prove(
        &self,
        session: &Self::Session,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (Self::Proof, Self::TargetInstance, Self::TargetWitness);

    fn verify(
        &self,
        session: &Self::Session,
        instance: &Self::SourceInstance,
        proof: &Self::Proof,
    ) -> VerificationResult<Self::TargetInstance>;
}

/// Adapter viewing a NARG as a one-message interactive argument.
///
/// The adapter fixes the NARG session because the `InteractiveArgument` API has
/// no separate session parameter. Its prover sends exactly one proof message;
/// its verifier reads that one message and performs the non-interactive check.
pub struct NargAsInteractiveArgument<N: NonInteractiveArgument> {
    pub narg: N,
    pub session: N::Session,
}

impl<N: NonInteractiveArgument> NargAsInteractiveArgument<N> {
    pub fn new(narg: N, session: N::Session) -> Self {
        Self { narg, session }
    }
}

impl<N> InteractiveArgument for NargAsInteractiveArgument<N>
where
    N: NonInteractiveArgument,
    N::Proof: Encoding<[u8]> + crate::NargSerialize + Deserialize,
{
    type Instance = N::Instance;
    type Witness = N::Witness;

    fn protocol_id(&self) -> impl AsRef<[u8]> {
        self.narg.protocol_id()
    }

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
        let proof: N::Proof = ch.read_prover_message()?;
        self.narg.verify(&self.session, instance, &proof)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;
    use crate::{pad_protocol_id, NargSerialize};

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
        fn read_prover_message<PM: Encoding<[u8]> + Deserialize>(
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
        type Proof = NargProof;

        fn protocol_id(&self) -> impl AsRef<[u8]> {
            pad_protocol_id(b"dummy narg")
        }

        fn prove(
            &self,
            _session: &Self::Session,
            instance: &Self::Instance,
            witness: &Self::Witness,
        ) -> Self::Proof {
            NargProof::from_bytes(vec![*instance as u8, *witness as u8])
        }

        fn verify(
            &self,
            _session: &Self::Session,
            instance: &Self::Instance,
            proof: &Self::Proof,
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
