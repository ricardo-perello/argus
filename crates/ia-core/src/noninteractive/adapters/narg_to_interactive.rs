//! Role-specific adapters viewing a NARG as a one-message interactive argument.

use crate::{
    ArgumentCore, ArgumentProverCore, InteractiveArgumentProver, InteractiveArgumentVerifier,
    NargProof, NonInteractiveArgumentProver, NonInteractiveArgumentVerifier, ProtocolCore,
    ProverChannel, VerificationResult, VerifierChannel,
};

/// NARG prover viewed as a one-message interactive prover.
pub struct NargProverAsInteractiveArgument<P: NonInteractiveArgumentProver> {
    pub narg: P,
    pub session: P::Session,
}

impl<P: NonInteractiveArgumentProver> NargProverAsInteractiveArgument<P> {
    pub fn new(narg: P, session: P::Session) -> Self {
        Self { narg, session }
    }
}

impl<P: NonInteractiveArgumentProver> ProtocolCore for NargProverAsInteractiveArgument<P> {
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        self.narg.protocol_id()
    }
}

impl<P: NonInteractiveArgumentProver> ArgumentCore for NargProverAsInteractiveArgument<P> {
    type Instance = P::Instance;
}

impl<P: NonInteractiveArgumentProver> ArgumentProverCore for NargProverAsInteractiveArgument<P> {
    type Witness = P::Witness;
}

impl<P: NonInteractiveArgumentProver> InteractiveArgumentProver
    for NargProverAsInteractiveArgument<P>
{
    fn prove<C: ProverChannel<Unit = u8>>(
        &self,
        ch: &mut C,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) {
        let proof = self.narg.prove(&self.session, instance, witness);
        ch.send_prover_message(&proof);
    }
}

/// NARG verifier viewed as a one-message interactive verifier.
pub struct NargVerifierAsInteractiveArgument<V: NonInteractiveArgumentVerifier> {
    pub narg: V,
    pub session: V::Session,
}

impl<V: NonInteractiveArgumentVerifier> NargVerifierAsInteractiveArgument<V> {
    pub fn new(narg: V, session: V::Session) -> Self {
        Self { narg, session }
    }
}

impl<V: NonInteractiveArgumentVerifier> ProtocolCore for NargVerifierAsInteractiveArgument<V> {
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        self.narg.protocol_id()
    }
}

impl<V: NonInteractiveArgumentVerifier> ArgumentCore for NargVerifierAsInteractiveArgument<V> {
    type Instance = V::Instance;
}

impl<V: NonInteractiveArgumentVerifier> InteractiveArgumentVerifier
    for NargVerifierAsInteractiveArgument<V>
{
    fn verify<C: VerifierChannel<Unit = u8>>(
        &self,
        ch: &mut C,
        instance: &Self::Instance,
    ) -> VerificationResult<()> {
        let proof: NargProof = ch.read_prover_message()?;
        self.narg.verify(&self.session, instance, &proof)
    }
}
