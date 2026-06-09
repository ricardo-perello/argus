//! Integration test: the preprocessed DSFS transcript binds BOTH the committed
//! verifier index and the per-claim instance before the first challenge.
//!
//! `ChallengeEchoArgument` echoes the verifier's challenge back, so any
//! divergence in the squeezed challenge (caused by a different committed index
//! or a different absorbed instance) is caught by the echo check.

use spongefish_dsfs as dsfs;

use ia_core::prelude::*;
use ia_core::{
    ArgumentCore, ArgumentProverCore, CommittedIndex, CommittedIndexBytes, Indexer, NargProof,
    ProtocolCore, ProverChannel, VerificationError, VerificationResult, VerifierChannel,
};

#[derive(Default)]
struct ChallengeEchoIndexer;

#[derive(Default)]
struct ChallengeEchoProver;

#[derive(Default)]
struct ChallengeEchoVerifier;

#[derive(Clone)]
struct EchoKey(Vec<u8>);

impl CommittedIndex for EchoKey {
    fn committed_index(&self) -> CommittedIndexBytes {
        CommittedIndexBytes::new(self.0.clone())
    }
}

fn protocol_id() -> [u8; 32] {
    ia_core::pad_protocol_id(b"prepared-argument-dsfs-test")
}

impl ProtocolCore for ChallengeEchoIndexer {
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        protocol_id()
    }
}

impl ArgumentCore for ChallengeEchoIndexer {
    type Instance = [u8; 1];
}

impl Indexer for ChallengeEchoIndexer {
    type Index = Vec<u8>;
    type ProverKey = EchoKey;
    type VerifierKey = EchoKey;

    fn preprocess(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
        (EchoKey(ix.clone()), EchoKey(ix.clone()))
    }
}

impl ProtocolCore for ChallengeEchoProver {
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        protocol_id()
    }
}

impl ArgumentCore for ChallengeEchoProver {
    type Instance = [u8; 1];
}

impl ArgumentProverCore for ChallengeEchoProver {
    type Witness = [u8; 1];
}

impl PreprocessingInteractiveArgumentProver for ChallengeEchoProver {
    type ProverKey = EchoKey;

    fn prove<P: ProverChannel<Unit = u8>>(
        &self,
        ch: &mut P,
        _: &Self::ProverKey,
        _: &Self::Instance,
        witness: &Self::Witness,
    ) {
        ch.send_prover_message(witness);
        let challenge: [u8; 8] = ch.read_verifier_message();
        ch.send_prover_message(&challenge);
    }
}

impl ProtocolCore for ChallengeEchoVerifier {
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        protocol_id()
    }
}

impl ArgumentCore for ChallengeEchoVerifier {
    type Instance = [u8; 1];
}

impl PreprocessingInteractiveArgumentVerifier for ChallengeEchoVerifier {
    type VerifierKey = EchoKey;

    fn verify<V: VerifierChannel<Unit = u8>>(
        &self,
        ch: &mut V,
        _: &Self::VerifierKey,
        _: &Self::Instance,
    ) -> VerificationResult<()> {
        let witness: [u8; 1] = ch.read_prover_message()?;
        if witness != [0xAB] {
            return Err(VerificationError);
        }

        let challenge: [u8; 8] = ch.send_verifier_message();
        let echoed: [u8; 8] = ch.read_prover_message()?;
        if challenge == echoed {
            Ok(())
        } else {
            Err(VerificationError)
        }
    }
}

#[test]
fn preprocessed_dsfs_absorbs_committed_index_and_instance() {
    let session = [0u8; 64];
    let witness = [0xABu8];

    let indexer = ChallengeEchoIndexer;
    let prover = dsfs::preprocessing_non_interactive_argument_prover::<_, [u8; 64], _>(
        ChallengeEchoProver,
        dsfs::Keccak::default(),
    );
    let verifier = dsfs::preprocessing_non_interactive_argument_verifier::<_, [u8; 64], _>(
        ChallengeEchoVerifier,
        dsfs::Keccak::default(),
    );

    // Prove under committed index [1,2,3] at instance [7].
    let (pk, vk) = indexer.preprocess(&vec![1u8, 2, 3]);
    assert_eq!(pk.committed_index(), vk.committed_index());
    let proof = prover.prove(&pk, &session, &[7u8], &witness);

    // Same committed index, same instance -> verifies.
    verifier
        .verify(&vk, &session, &[7u8], &proof)
        .expect("same committed index and same instance verify");

    // Changing only the verifier-key commitment must change the transcript.
    let (_pk_other, vk_other_index) = indexer.preprocess(&vec![9u8, 9, 9]);
    assert!(
        verifier
            .verify(&vk_other_index, &session, &[7u8], &proof)
            .is_err(),
        "changing only the committed index must change the DSFS transcript"
    );

    // Changing only the per-claim instance must change the transcript.
    assert!(
        verifier.verify(&vk, &session, &[8u8], &proof).is_err(),
        "changing only the per-claim instance must change the DSFS transcript"
    );

    // Verifiers consume exactly one proof and reject trailing bytes.
    let mut trailing = proof.into_bytes();
    trailing.push(0);
    assert!(
        verifier
            .verify(&vk, &session, &[7u8], &NargProof::from_bytes(trailing))
            .is_err()
    );
}
