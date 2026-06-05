//! `CombinedIA`: combine a prover-only and a verifier-only interactive body into a
//! full interactive argument.
//!
//! This is the body-level mirror of `spongefish_dsfs::CombinedNarg` (which combines
//! at the compiled-NARG level). It lets two independently-authored halves — a body
//! that implements only [`InteractiveArgumentProver`] and one that implements only
//! [`InteractiveArgumentVerifier`] — be glued into a single value that implements
//! both halves, hence (via the blanket conjunction) a full [`InteractiveArgument`].

use crate::{
    ArgumentCore, InteractiveArgumentProver, InteractiveArgumentVerifier, ProtocolCore,
    ProverChannel, VerificationResult, VerifierChannel,
};

/// Combine a prover-only body `P` and a verifier-only body `V`: `P` supplies
/// `prove`, `V` supplies `verify`.
///
/// The two bodies must describe the *same* protocol — identical instance / witness
/// types (enforced at the type level by the bounds) and identical `protocol_id`
/// (checked at construction with a `debug_assert`). The result implements both
/// interactive halves, so the blanket conjunction makes it a full
/// [`crate::InteractiveArgument`] that can be compiled through DSFS like any other
/// body.
pub struct CombinedIA<P, V> {
    pub prover: P,
    pub verifier: V,
}

impl<P, V> CombinedIA<P, V>
where
    P: InteractiveArgumentProver,
    V: InteractiveArgumentVerifier<Instance = P::Instance, Witness = P::Witness>,
{
    /// Combine a prover and a verifier body, asserting they agree on `protocol_id`.
    #[must_use]
    pub fn new(prover: P, verifier: V) -> Self {
        let p = prover.protocol_id();
        let v = verifier.protocol_id();
        debug_assert_eq!(
            p.as_ref(),
            v.as_ref(),
            "CombinedIA: prover and verifier disagree on protocol_id; they are not the same protocol",
        );
        drop((p, v));
        Self { prover, verifier }
    }
}

impl<P: ProtocolCore, V> ProtocolCore for CombinedIA<P, V> {
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        self.prover.protocol_id()
    }
}

impl<P: ArgumentCore, V> ArgumentCore for CombinedIA<P, V> {
    type Instance = P::Instance;
    type Witness = P::Witness;
}

impl<P, V> InteractiveArgumentProver for CombinedIA<P, V>
where
    P: InteractiveArgumentProver,
{
    fn prove<Ch: ProverChannel<Unit = u8>>(
        &self,
        ch: &mut Ch,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) {
        self.prover.prove(ch, instance, witness)
    }
}

impl<P, V> InteractiveArgumentVerifier for CombinedIA<P, V>
where
    P: ArgumentCore,
    V: InteractiveArgumentVerifier<Instance = P::Instance>,
{
    fn verify<Ch: VerifierChannel<Unit = u8>>(
        &self,
        ch: &mut Ch,
        instance: &Self::Instance,
    ) -> VerificationResult<()> {
        self.verifier.verify(ch, instance)
    }
}
