//! Non-interactive argument abstractions.
//!
//! The IA traits model public-coin protocols as channel programs. The traits in
//! this module model the result after a compiler such as DSFS has removed the
//! verifier's live randomness and produced a single non-interactive artifact.
//!
//! `ia-core` owns these types because they are abstract protocol vocabulary:
//! they say what a non-interactive argument or reduction is, but they do not
//! specify Fiat-Shamir, duplex sponges, domain separation, or any concrete proof
//! layout. Concrete compilers live outside this crate and implement these traits.
//!
//! The proof artifact is always [`NargProof`] (byte-oriented). The trait used
//! to leave it generic, but every implementor in the workspace returned
//! `NargProof` regardless, so the associated type was unused flexibility.
//! Compilers that want structured (non-byte) proofs should introduce a separate
//! trait rather than parameterizing this one.

extern crate alloc;

use alloc::vec::Vec;

use crate::{
    ArgumentCore, Encoding, InteractiveArgument, NargDeserialize, ProtocolCore, ProverChannel,
    VerificationError, VerificationResult, VerifierChannel,
};

/// Opaque byte artifact produced by a non-interactive argument compiler.
///
/// `NargProof` deliberately carries no transcript semantics: sponge choice,
/// salt policy, domain separation, and proof layout are owned by the compiler
/// that produced the bytes.
///
/// The top-level proof artifact is raw bytes: [`NargProof::as_bytes`] and
/// [`NargProof::into_bytes`] expose exactly the byte string emitted by the
/// compiler. When a proof itself is sent as a channel message, its
/// [`Encoding`] implementation is length-delimited as
/// `u64_le(length) || proof_bytes`. This keeps "proof as an artifact" separate
/// from "proof as a typed prover message", where variable-length data must be
/// self-delimiting.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NargProof(Vec<u8>);

impl NargProof {
    /// Wrap raw proof bytes produced by a non-interactive compiler.
    ///
    /// The bytes are not interpreted or normalized.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Consume the proof and return the raw proof bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Borrow the raw proof bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Return the raw proof length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Return whether the raw proof byte string is empty.
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
///
/// A `NonInteractiveArgument` verifies membership of an `Instance` using a
/// [`NargProof`], with optional session data bound into the compiled transcript.
/// Unlike [`InteractiveArgument`], there is no channel: the prover returns a
/// proof artifact and the verifier checks that artifact.
pub trait NonInteractiveArgument {
    /// Public session or context data bound into the non-interactive proof.
    type Session;
    /// Public statement being proved.
    type Instance;
    /// Private witness used by the prover.
    type Witness;

    /// Protocol identifier for the non-interactive argument.
    ///
    /// For compilers, this should identify the compiled proof system, not only
    /// the underlying interactive protocol. If the proof layout, sponge choice,
    /// salt policy, or transcript derivation changes, the compiler-level domain
    /// separation must change as well.
    fn protocol_id(&self) -> impl AsRef<[u8]>;

    /// Produce a non-interactive proof for `instance` using `witness`.
    fn prove(
        &self,
        session: &Self::Session,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> NargProof;

    /// Verify a non-interactive proof for `instance`.
    fn verify(
        &self,
        session: &Self::Session,
        instance: &Self::Instance,
        proof: &NargProof,
    ) -> VerificationResult<()>;
}

/// Abstract non-interactive reduction.
///
/// A non-interactive reduction proves that a source instance reduces to a target
/// instance. Verification returns the target instance instead of a boolean
/// accept/reject result, mirroring [`crate::InteractiveReduction`].
///
/// Proving returns the proof plus the target instance/witness pair so callers can
/// continue a reduction pipeline without replaying the verifier.
pub trait NonInteractiveReduction {
    /// Public session or context data bound into the non-interactive proof.
    type Session;
    /// Public source statement before reduction.
    type SourceInstance;
    /// Public target statement produced by the reduction.
    type TargetInstance;
    /// Private witness for the source statement.
    type SourceWitness;
    /// Private witness for the target statement produced by the prover.
    type TargetWitness;

    /// Protocol identifier for the non-interactive reduction.
    fn protocol_id(&self) -> impl AsRef<[u8]>;

    /// Produce a reduction proof and the reduced target statement/witness pair.
    fn prove(
        &self,
        session: &Self::Session,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (NargProof, Self::TargetInstance, Self::TargetWitness);

    /// Verify a reduction proof and return the reduced target statement.
    fn verify(
        &self,
        session: &Self::Session,
        instance: &Self::SourceInstance,
        proof: &NargProof,
    ) -> VerificationResult<Self::TargetInstance>;
}

/// Non-interactive argument produced from a preprocessed (indexed) body.
///
/// A marker trait combining [`NonInteractiveArgument`] with the
/// [`Preprocessed`](crate::indexed::Preprocessed) capability. The actual
/// accessors (`prover_key`, `verifier_key`, `committed_index`) live on
/// `Preprocessed`, which is the single discoverable home for preprocessing
/// keys regardless of which lattice plane (IA/IR or NARG) the wrapper sits on.
///
/// Plain NARGs (e.g. `DsfsArgument<plain_ia>`) do NOT implement `Preprocessed` and
/// therefore do NOT satisfy this bound: the type system enforces that a
/// generic consumer with bound `T: PreprocessingNonInteractiveArgument` provably
/// receives a NARG built from a preprocessed body.
pub trait PreprocessingNonInteractiveArgument:
    NonInteractiveArgument + crate::indexed::Preprocessed
{
}

impl<T> PreprocessingNonInteractiveArgument for T where
    T: NonInteractiveArgument + crate::indexed::Preprocessed
{
}

/// Non-interactive reduction produced from a preprocessed (indexed) body.
///
/// Reduction counterpart to [`PreprocessingNonInteractiveArgument`]; same composition,
/// same strong-typing argument.
pub trait PreprocessingNonInteractiveReduction:
    NonInteractiveReduction + crate::indexed::Preprocessed
{
}

impl<T> PreprocessingNonInteractiveReduction for T where
    T: NonInteractiveReduction + crate::indexed::Preprocessed
{
}

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
    use crate::{NargSerialize, pad_protocol_id};

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
