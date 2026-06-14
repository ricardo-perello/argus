//! σ-proofs transcript-init compatibility shim (legacy `StdHash` path).
//!
//! This `TranscriptSponge` trait used to live in `spongefish-dsfs`. It was moved
//! here because sigma-bridge is its **only** consumer, and the one behavior it
//! carries is legacy: the `StdHash` (SHAKE128) init path.
//!
//! Two `StdHash` transcript initialisations exist in the tree:
//!
//! | path | `StdHash` init | used by |
//! | --- | --- | --- |
//! | `DomainSeparator::to_prover` (duplex) | `absorb(domsep) ‖ absorb(instance)` | the DSFS compiler (all sponges) |
//! | `DomainSeparator::std_prover` (this shim) | `absorb(domsep ‖ SHAKE-rate pad) ‖ absorb(instance)` | σ-proofs SHAKE128 golden vectors |
//!
//! The DSFS compiler already treats `StdHash` the convergence-aligned way
//! (`to_prover`), so its `StdHash` proofs are **intentionally not byte-compatible**
//! with the legacy σ-proofs layout. This shim preserves the legacy `std_prover`
//! padding *only* so the σ-proofs vectors keep matching upstream.
//!
//! Per [ADR 0004](../../docs/adr/0004-stdhash-transcript-init-legacy.md): when
//! spongefish unifies the `StdHash` init with the duplex path, delete this shim,
//! switch the σ-proofs `StdHash` path to `to_prover`, and regenerate the vectors.
//! The tripwire test below fails the moment that convergence lands.

use spongefish::{DomainSeparator, DuplexSpongeInterface, Encoding, ProverState, VerifierState};
use spongefish_dsfs::{Keccak, SpongeInfo, StdHash};

/// Build spongefish prover/verifier states from the public inputs that define the
/// Fiat–Shamir transcript (protocol id, session id, instance bytes), using the
/// **legacy** per-sponge init expected by the σ-proofs vectors.
///
/// `Keccak` uses the duplex path ([`DomainSeparator::to_prover`] /
/// [`DomainSeparator::to_verifier`]) — identical to the DSFS compiler. `StdHash`
/// uses the legacy `std_prover` / `std_verifier` path (see the module docs).
pub trait TranscriptSponge: DuplexSpongeInterface<U = u8> + Sized {
    fn prover_state<I: Encoding>(
        self,
        protocol_id: [u8; 64],
        session: [u8; 64],
        instance: &I,
    ) -> ProverState<Self>;

    fn verifier_state<'a, I: Encoding>(
        self,
        protocol_id: [u8; 64],
        session: [u8; 64],
        instance: &I,
        narg_string: &'a [u8],
    ) -> VerifierState<'a, Self>;
}

impl TranscriptSponge for Keccak {
    fn prover_state<I: Encoding>(
        self,
        protocol_id: [u8; 64],
        session: [u8; 64],
        instance: &I,
    ) -> ProverState<Self> {
        let domsep =
            DomainSeparator::derive(protocol_id.as_ref(), Self::SPONGE_INFO, session.as_ref())
                .instance(instance);
        domsep.to_prover(self)
    }

    fn verifier_state<'a, I: Encoding>(
        self,
        protocol_id: [u8; 64],
        session: [u8; 64],
        instance: &I,
        narg_string: &'a [u8],
    ) -> VerifierState<'a, Self> {
        let domsep =
            DomainSeparator::derive(protocol_id.as_ref(), Self::SPONGE_INFO, session.as_ref())
                .instance(instance);
        domsep.to_verifier(self, narg_string)
    }
}

impl TranscriptSponge for StdHash {
    fn prover_state<I: Encoding>(
        self,
        protocol_id: [u8; 64],
        session: [u8; 64],
        instance: &I,
    ) -> ProverState<Self> {
        // IMPORTANT (legacy): ignore `self` and use spongefish `std_prover` init.
        let domsep = DomainSeparator::derive(
            protocol_id.as_ref(),
            <Self as SpongeInfo>::SPONGE_INFO,
            session.as_ref(),
        )
        .instance(instance);
        domsep.std_prover()
    }

    fn verifier_state<'a, I: Encoding>(
        self,
        protocol_id: [u8; 64],
        session: [u8; 64],
        instance: &I,
        narg_string: &'a [u8],
    ) -> VerifierState<'a, Self> {
        // IMPORTANT (legacy): ignore `self` and use spongefish `std_verifier` init.
        let domsep = DomainSeparator::derive(
            protocol_id.as_ref(),
            <Self as SpongeInfo>::SPONGE_INFO,
            session.as_ref(),
        )
        .instance(instance);
        domsep.std_verifier(narg_string)
    }
}

#[cfg(test)]
mod tests {
    use spongefish::{DomainSeparator, StdHash};
    use spongefish_dsfs::SpongeInfo;

    /// Tripwire for the legacy `StdHash` divergence (see module docs + ADR 0004).
    ///
    /// While the DSFS compiler's `to_prover` init and the legacy `std_prover` init
    /// differ, this passes. If spongefish unifies them, the first squeezed
    /// challenge becomes equal and this test FAILS — that is the signal to delete
    /// this shim, move the σ-proofs `StdHash` path onto `to_prover`, and
    /// regenerate the σ-proofs golden vectors.
    #[test]
    fn stdhash_to_prover_and_std_prover_inits_still_diverge() {
        let domsep = DomainSeparator::derive(
            b"sigma-bridge/tripwire",
            <StdHash as SpongeInfo>::SPONGE_INFO,
            b"session",
        )
        .instance(&[0u8; 4]);

        let mut via_to_prover = domsep.to_prover(StdHash::default()); // compiler path
        let mut via_std_prover = domsep.std_prover(); // legacy σ-proofs path

        let a: [u8; 16] = via_to_prover.verifier_message();
        let b: [u8; 16] = via_std_prover.verifier_message();

        assert_ne!(
            a, b,
            "StdHash `to_prover` and `std_prover` inits have CONVERGED. spongefish \
             unified the path: delete the sigma-bridge TranscriptSponge shim, switch \
             the StdHash sigma-proofs path to `to_prover`, and regenerate the \
             sigma-proofs golden vectors (ADR 0004)."
        );
    }
}
