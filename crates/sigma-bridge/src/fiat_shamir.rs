//! Batchable and compact non-interactive Σ proofs (Nizk-compatible transcript).

use alloc::vec::Vec;

use dsfs::{ByteDuplexSponge, SpongeProver, SpongeVerifier};
use spongefish::{DomainSeparator, NargDeserialize, NargSerialize};

use crate::session::derive_session_id;
use crate::traits::{ScalarRng, SigmaBridgeError, SigmaProtocol, SigmaProtocolSimulator};

fn serialize_messages<T: NargSerialize>(messages: &[T]) -> Vec<u8> {
    let mut out = Vec::new();
    for message in messages {
        message.serialize_into_narg(&mut out);
    }
    out
}

fn serialize_messages_into<T: NargSerialize>(messages: &[T], out: &mut Vec<u8>) {
    for message in messages {
        message.serialize_into_narg(out);
    }
}

fn deserialize_messages<T: NargDeserialize>(
    len: usize,
    buf: &mut &[u8],
) -> Result<Vec<T>, SigmaBridgeError> {
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(T::deserialize_from_narg(buf).map_err(|_| SigmaBridgeError::VerificationFailed)?);
    }
    Ok(out)
}

/// Prove (batchable): commitment bytes prepended to serialized responses.
pub fn prove_batchable_sigma<P, H>(
    sponge: H,
    session_id: &[u8],
    interactive_proof: &P,
    witness: &P::Witness,
    rng: &mut impl ScalarRng,
) -> Result<Vec<u8>, SigmaBridgeError>
where
    P: SigmaProtocol,
    P::Challenge: PartialEq,
    H: ByteDuplexSponge,
{
    let protocol_id = interactive_proof.protocol_identifier();
    let instance_label = interactive_proof.instance_label().as_ref().to_vec();
    let domsep = DomainSeparator::new(protocol_id)
        .session(derive_session_id(session_id))
        .instance(&instance_label);

    let mut transcript = SpongeProver::new(domsep.to_prover(sponge));
    let (commitment, ip_state) = interactive_proof
        .prover_commit(witness, rng)
        .map_err(|_| SigmaBridgeError::ProverFailed)?;
    let commitment_bytes = serialize_messages(&commitment);
    transcript.public_message(commitment_bytes.as_slice());
    let challenge = transcript.verifier_message::<P::Challenge>();
    let response = interactive_proof
        .prover_response(ip_state, &challenge)
        .map_err(|_| SigmaBridgeError::ProverFailed)?;
    let mut proof = commitment_bytes;
    serialize_messages_into(&response, &mut proof);
    Ok(proof)
}

/// Verify batchable proof bytes.
pub fn verify_batchable_sigma<P, H>(
    sponge: H,
    session_id: &[u8],
    interactive_proof: &P,
    narg_string: &[u8],
) -> Result<(), SigmaBridgeError>
where
    P: SigmaProtocol,
    P::Challenge: PartialEq,
    H: ByteDuplexSponge,
{
    let protocol_id = interactive_proof.protocol_identifier();
    let instance_label = interactive_proof.instance_label().as_ref().to_vec();
    let commitment_len = interactive_proof.commitment_len();
    let response_len = interactive_proof.response_len();
    let domsep = DomainSeparator::new(protocol_id)
        .session(derive_session_id(session_id))
        .instance(&instance_label);

    let mut transcript = SpongeVerifier::new(domsep.to_verifier(sponge, narg_string));
    let commitment = transcript
        .prover_messages_vec::<P::Commitment>(commitment_len)
        .map_err(SigmaBridgeError::from)?;
    let challenge = transcript.verifier_message::<P::Challenge>();
    let response = transcript
        .prover_messages_vec::<P::Response>(response_len)
        .map_err(SigmaBridgeError::from)?;
    transcript.check_eof().map_err(SigmaBridgeError::from)?;
    interactive_proof
        .verifier(&commitment, &challenge, &response)
        .map_err(|_| SigmaBridgeError::VerificationFailed)
}

/// Prove (compact): serialized challenge then responses.
pub fn prove_compact_sigma<P, H>(
    sponge: H,
    session_id: &[u8],
    interactive_proof: &P,
    witness: &P::Witness,
    rng: &mut impl ScalarRng,
) -> Result<Vec<u8>, SigmaBridgeError>
where
    P: SigmaProtocol + SigmaProtocolSimulator,
    P::Challenge: PartialEq + NargDeserialize + NargSerialize,
    H: ByteDuplexSponge,
{
    let protocol_id = interactive_proof.protocol_identifier();
    let instance_label = interactive_proof.instance_label().as_ref().to_vec();
    let domsep = DomainSeparator::new(protocol_id)
        .session(derive_session_id(session_id))
        .instance(&instance_label);

    let mut transcript = SpongeProver::new(domsep.to_prover(sponge));
    let (commitment, ip_state) = interactive_proof
        .prover_commit(witness, rng)
        .map_err(|_| SigmaBridgeError::ProverFailed)?;
    let commitment_bytes = serialize_messages(&commitment);
    transcript.public_message(commitment_bytes.as_slice());
    let challenge = transcript.verifier_message::<P::Challenge>();
    let response = interactive_proof
        .prover_response(ip_state, &challenge)
        .map_err(|_| SigmaBridgeError::ProverFailed)?;

    let mut proof = Vec::new();
    challenge.serialize_into_narg(&mut proof);
    serialize_messages_into(&response, &mut proof);
    Ok(proof)
}

/// Verify compact proof.
pub fn verify_compact_sigma<P, H>(
    sponge: H,
    session_id: &[u8],
    interactive_proof: &P,
    proof: &[u8],
) -> Result<(), SigmaBridgeError>
where
    P: SigmaProtocol + SigmaProtocolSimulator,
    P::Challenge: PartialEq + NargDeserialize + NargSerialize,
    H: ByteDuplexSponge,
{
    let mut cursor = proof;
    let protocol_id = interactive_proof.protocol_identifier();
    let instance_label = interactive_proof.instance_label().as_ref().to_vec();
    let challenge = P::Challenge::deserialize_from_narg(&mut cursor)
        .map_err(|_| SigmaBridgeError::VerificationFailed)?;
    let response_len = interactive_proof.response_len();
    let response = deserialize_messages(response_len, &mut cursor)?;
    if !cursor.is_empty() {
        return Err(SigmaBridgeError::VerificationFailed);
    }

    let commitment = interactive_proof
        .simulate_commitment(&challenge, &response)
        .map_err(|_| SigmaBridgeError::VerificationFailed)?;
    let commitment_bytes = serialize_messages(&commitment);
    let domsep = DomainSeparator::new(protocol_id)
        .session(derive_session_id(session_id))
        .instance(&instance_label);

    let mut transcript = SpongeVerifier::new(domsep.to_verifier(sponge, &[]));
    transcript.public_message(commitment_bytes.as_slice());
    let recomputed_challenge = transcript.verifier_message::<P::Challenge>();
    if challenge != recomputed_challenge {
        return Err(SigmaBridgeError::VerificationFailed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;
    use rand_core::SeedableRng;

    struct ToySigma {
        instance: Vec<u8>,
    }

    impl SigmaProtocol for ToySigma {
        type Commitment = u32;
        type Challenge = u32;
        type Response = u32;
        type ProverState = u32;
        type Witness = u32;

        fn prover_commit(
            &self,
            witness: &Self::Witness,
            _rng: &mut impl ScalarRng,
        ) -> Result<(Vec<Self::Commitment>, Self::ProverState), SigmaBridgeError> {
            Ok((vec![*witness], *witness))
        }

        fn prover_response(
            &self,
            state: Self::ProverState,
            challenge: &Self::Challenge,
        ) -> Result<Vec<Self::Response>, SigmaBridgeError> {
            Ok(vec![state ^ challenge])
        }

        fn verifier(
            &self,
            _commitment: &[Self::Commitment],
            _challenge: &Self::Challenge,
            _response: &[Self::Response],
        ) -> Result<(), ()> {
            Ok(())
        }

        fn commitment_len(&self) -> usize {
            1
        }

        fn response_len(&self) -> usize {
            1
        }

        fn protocol_identifier(&self) -> [u8; 64] {
            spongefish::protocol_id(core::format_args!("sigma-bridge/toy"))
        }

        fn instance_label(&self) -> impl AsRef<[u8]> {
            self.instance.as_slice()
        }
    }

    impl SigmaProtocolSimulator for ToySigma {
        fn simulate_commitment(
            &self,
            challenge: &Self::Challenge,
            response: &[Self::Response],
        ) -> Result<Vec<Self::Commitment>, SigmaBridgeError> {
            let r = response.first().ok_or(SigmaBridgeError::ProverFailed)?;
            Ok(vec![r ^ challenge])
        }
    }

    #[test]
    fn batchable_round_trip_std_hash() {
        let p = ToySigma {
            instance: b"inst".to_vec(),
        };
        let w = 0x0102_0304_u32;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([7u8; 32]);
        let proof = prove_batchable_sigma(dsfs::StdHash::default(), b"sess", &p, &w, &mut rng)
            .expect("prove");
        verify_batchable_sigma(dsfs::StdHash::default(), b"sess", &p, &proof).expect("verify");
    }

    #[test]
    fn batchable_round_trip_keccak() {
        let p = ToySigma {
            instance: b"inst".to_vec(),
        };
        let w = 0x0102_0304_u32;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([7u8; 32]);
        let proof = prove_batchable_sigma(dsfs::Keccak::default(), b"sess", &p, &w, &mut rng)
            .expect("prove");
        verify_batchable_sigma(dsfs::Keccak::default(), b"sess", &p, &proof).expect("verify");
    }

    #[test]
    fn compact_round_trip_std_hash() {
        let p = ToySigma {
            instance: b"inst".to_vec(),
        };
        let w = 0x0102_0304_u32;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([9u8; 32]);
        let proof = prove_compact_sigma(dsfs::StdHash::default(), b"sess2", &p, &w, &mut rng)
            .expect("prove");
        verify_compact_sigma(dsfs::StdHash::default(), b"sess2", &p, &proof).expect("verify");
    }
}
