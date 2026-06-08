//! Role-first interactive-argument adapters for [`SigmaProtocol`].
//!
//! [`SigmaIA`] is the encoded public instance. [`SigmaIAProver`] and
//! [`SigmaIAVerifier`] are independent executable roles that retain the exact
//! 64-byte upstream protocol identifier, including identifiers computed from a
//! runtime composition tree.

extern crate alloc;

use alloc::vec::Vec;
use core::marker::PhantomData;

use ia_core::{
    ArgumentCore, ArgumentProverCore, InteractiveArgumentProver, InteractiveArgumentVerifier,
    ProtocolCore, ProverChannel, VerificationError, VerificationResult, VerifierChannel,
};
use rand_chacha::rand_core::SeedableRng;
use sigma_proofs::traits::SigmaProtocol;
use spongefish::Encoding;

/// Public sigma-protocol instance absorbed by DSFS.
pub struct SigmaIA<S>(pub S);

/// Prover adapter for a sigma-protocol instance.
pub struct SigmaIAProver<S> {
    protocol_id: [u8; 64],
    _protocol: PhantomData<S>,
}

/// Verifier adapter for a sigma-protocol instance.
pub struct SigmaIAVerifier<S> {
    protocol_id: [u8; 64],
    _protocol: PhantomData<S>,
}

impl<S: SigmaProtocol> SigmaIAProver<S> {
    #[must_use]
    pub fn new(instance: &SigmaIA<S>) -> Self {
        Self {
            protocol_id: instance.0.protocol_identifier(),
            _protocol: PhantomData,
        }
    }
}

impl<S: SigmaProtocol> SigmaIAVerifier<S> {
    #[must_use]
    pub fn new(instance: &SigmaIA<S>) -> Self {
        Self {
            protocol_id: instance.0.protocol_identifier(),
            _protocol: PhantomData,
        }
    }
}

impl<S> ProtocolCore for SigmaIAProver<S> {
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        self.protocol_id
    }
}

impl<S> ProtocolCore for SigmaIAVerifier<S> {
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        self.protocol_id
    }
}

impl<S: SigmaProtocol> ArgumentCore for SigmaIAProver<S> {
    type Instance = SigmaIA<S>;
}

impl<S: SigmaProtocol> ArgumentProverCore for SigmaIAProver<S> {
    type Witness = (S::Witness, [u8; 32]);
}

impl<S: SigmaProtocol> ArgumentCore for SigmaIAVerifier<S> {
    type Instance = SigmaIA<S>;
}

impl<S> InteractiveArgumentProver for SigmaIAProver<S>
where
    S: SigmaProtocol,
{
    fn prove<P: ProverChannel<Unit = u8>>(
        &self,
        ch: &mut P,
        instance: &SigmaIA<S>,
        witness: &(S::Witness, [u8; 32]),
    ) {
        let (witness, seed) = witness;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(*seed);

        let (commitment, state) = instance
            .0
            .prover_commit(witness, &mut rng)
            .expect("honest prover commit must not fail");

        for value in &commitment {
            ch.send_prover_message(value);
        }

        let challenge: S::Challenge = ch.read_verifier_message();
        let response = instance
            .0
            .prover_response(state, &challenge)
            .expect("honest prover response must not fail");

        for value in &response {
            ch.send_prover_message(value);
        }
    }
}

impl<S> InteractiveArgumentVerifier for SigmaIAVerifier<S>
where
    S: SigmaProtocol,
{
    fn verify<V: VerifierChannel<Unit = u8>>(
        &self,
        ch: &mut V,
        instance: &SigmaIA<S>,
    ) -> VerificationResult<()> {
        let mut commitment = Vec::with_capacity(instance.0.commitment_len());
        for _ in 0..instance.0.commitment_len() {
            commitment.push(ch.read_prover_message::<S::Commitment>()?);
        }

        let challenge: S::Challenge = ch.send_verifier_message();

        let mut response = Vec::with_capacity(instance.0.response_len());
        for _ in 0..instance.0.response_len() {
            response.push(ch.read_prover_message::<S::Response>()?);
        }

        instance
            .0
            .verifier(&commitment, &challenge, &response)
            .map_err(|_| VerificationError)
    }
}

impl<S: SigmaProtocol> Encoding for SigmaIA<S> {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.0.instance_label().as_ref().to_vec()
    }
}
