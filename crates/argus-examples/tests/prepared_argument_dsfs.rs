use spongefish_dsfs as dsfs;

use ia_core::{
    ArgumentCore, CommittedIndexBytes, IndexedInstance, NonInteractiveArgument, PreparedArgument,
    PreprocessingCore, PreprocessingInteractiveArgument, ProtocolCore, ProverChannel,
    VerificationError, VerificationResult, VerifierChannel, VerifierKeyCommitment,
};

#[derive(Default)]
struct ChallengeEchoArgument;

#[derive(Clone)]
struct EchoVerifierKey(Vec<u8>);

impl VerifierKeyCommitment for EchoVerifierKey {
    fn committed_index(&self) -> CommittedIndexBytes {
        CommittedIndexBytes::new(self.0.clone())
    }
}

impl ProtocolCore for ChallengeEchoArgument {
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        ia_core::pad_protocol_id(b"prepared-argument-dsfs-test")
    }
}

impl ArgumentCore for ChallengeEchoArgument {
    type Instance = [u8; 1];
    type Witness = [u8; 1];
}

impl PreprocessingCore for ChallengeEchoArgument {
    type Index = Vec<u8>;
    type ProverKey = ();
    type VerifierKey = EchoVerifierKey;

    fn index(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
        ((), EchoVerifierKey(ix.clone()))
    }
}

impl PreprocessingInteractiveArgument for ChallengeEchoArgument {
    fn prove<P: ProverChannel>(
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

    fn verify<V: VerifierChannel>(
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

type PreparedEchoArgument = PreparedArgument<ChallengeEchoArgument>;
type PreparedEchoDsfs = dsfs::DsfsArgument<PreparedEchoArgument, [u8; 64]>;

fn prepared_plain_dsfs(
    ix: &[u8],
    instance: [u8; 1],
) -> (PreparedEchoDsfs, IndexedInstance<[u8; 1]>) {
    let prepared = PreparedArgument::prepare(ChallengeEchoArgument, &ix.to_vec());
    let indexed_instance = prepared.indexed_instance(instance);
    let narg =
        dsfs::plain_non_interactive_argument::<_, [u8; 64], _>(prepared, dsfs::Keccak::default());
    (narg, indexed_instance)
}

#[test]
fn prepared_argument_then_plain_dsfs_absorbs_committed_index_and_instance() {
    let session = [0u8; 64];
    let witness = [0xAB];

    let (prover, prover_instance) = prepared_plain_dsfs(&[1, 2, 3], [7]);
    let proof = prover.prove(&session, &prover_instance, &witness);

    let (verifier, verifier_instance) = prepared_plain_dsfs(&[1, 2, 3], [7]);
    verifier
        .verify(&session, &verifier_instance, &proof)
        .expect("same committed index and same instance verify");

    let (different_index_verifier, same_inner_instance) = prepared_plain_dsfs(&[9, 9, 9], [7]);
    assert!(
        different_index_verifier
            .verify(&session, &same_inner_instance, &proof)
            .is_err(),
        "changing only the verifier-key commitment must change the DSFS transcript"
    );

    let (different_instance_verifier, different_inner_instance) =
        prepared_plain_dsfs(&[1, 2, 3], [8]);
    assert!(
        different_instance_verifier
            .verify(&session, &different_inner_instance, &proof)
            .is_err(),
        "changing only the per-claim instance must change the DSFS transcript"
    );
}
