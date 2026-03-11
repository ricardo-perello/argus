//! DSFS compiler: Duplex-Sponge Fiat-Shamir transformation (Construction 4.3, Chiesa-Orru 2025).
//!
//! Wraps spongefish's `ProverState` and `VerifierState` behind ia-core's
//! abstract channel traits. This is the **only** layer that touches the sponge.
//!
//! Supports both interactive arguments (`prove`/`verify`) and interactive
//! oracle reductions (`prove_reduction`/`verify_reduction`).
#![no_std]
extern crate alloc;

use alloc::vec::Vec;

use ia_core::{Prove, ProverChannel, ReduceProve, ReduceVerify, VerifierChannel, Verify};
use spongefish::{Decoding, DomainSeparator, Encoding, NargDeserialize, ProverState, VerifierState};

// ---------------------------------------------------------------------------
// Sponge-backed channel: prover side
// ---------------------------------------------------------------------------

/// Wraps `spongefish::ProverState` as an ia-core `ProverChannel`.
pub struct SpongeProver {
    state: ProverState,
}

impl ProverChannel for SpongeProver {
    fn send_prover_message<PM: Encoding>(&mut self, msg: &PM) {
        self.state.prover_message(msg);
    }

    fn read_verifier_message<VM: Decoding>(&mut self) -> VM {
        self.state.verifier_message()
    }
}

// ---------------------------------------------------------------------------
// Sponge-backed channel: verifier side
// ---------------------------------------------------------------------------

/// Wraps `spongefish::VerifierState` as an ia-core `VerifierChannel`.
pub struct SpongeVerifier<'a> {
    state: VerifierState<'a>,
}

impl VerifierChannel for SpongeVerifier<'_> {
    fn read_prover_message<PM: Encoding + NargDeserialize>(
        &mut self,
    ) -> ia_core::VerificationResult<PM> {
        self.state
            .prover_message()
            .map_err(|_| ia_core::VerificationError)
    }

    fn send_verifier_message<VM: Decoding>(&mut self) -> VM {
        self.state.verifier_message()
    }
}

// ---------------------------------------------------------------------------
// DSFS compiler functions
// ---------------------------------------------------------------------------

/// Non-interactive prover: creates a sponge channel, runs `IA::prove`, returns the NARG string.
pub fn prove<IA>(
    session: [u8; 64],
    instance: &IA::Instance,
    witness: &IA::Witness,
) -> Vec<u8>
where
    IA: Prove<SpongeProver>,
    IA::Instance: Encoding,
{
    let domsep = DomainSeparator::new(IA::protocol_id())
        .session(session)
        .instance(instance);

    let mut spongefish_prover_ch = SpongeProver {
        state: domsep.std_prover(),
    };
    IA::prove(&mut spongefish_prover_ch, instance, witness);
    spongefish_prover_ch.state.narg_string().to_vec()
}

/// Non-interactive verifier: creates a sponge channel, runs `IA::verify`, checks EOF.
pub fn verify<'a, IA>(
    session: [u8; 64],
    instance: &IA::Instance,
    proof: &'a [u8],
) -> ia_core::VerificationResult<()>
where
    IA: Verify<SpongeVerifier<'a>>,
    IA::Instance: Encoding,
{
    let domsep = DomainSeparator::new(IA::protocol_id())
        .session(session)
        .instance(instance);

    let mut spongefish_verifier_ch = SpongeVerifier {
        state: domsep.std_verifier(proof),
    };
    IA::verify(&mut spongefish_verifier_ch, instance)?;
    spongefish_verifier_ch
        .state
        .check_eof()
        .map_err(|_| ia_core::VerificationError)
}

// ---------------------------------------------------------------------------
// DSFS compiler functions for interactive reductions
// ---------------------------------------------------------------------------

/// Non-interactive prover for an IOR: creates a sponge channel, runs
/// `IR::prove`, returns the NARG string.
pub fn prove_reduction<IR>(
    session: [u8; 64],
    instance: &IR::SourceInstance,
    witness: &IR::Witness,
) -> Vec<u8>
where
    IR: ReduceProve<SpongeProver>,
    IR::SourceInstance: Encoding,
{
    let domsep = DomainSeparator::new(IR::protocol_id())
        .session(session)
        .instance(instance);

    let mut spongefish_prover_ch = SpongeProver {
        state: domsep.std_prover(),
    };
    IR::prove(&mut spongefish_prover_ch, instance, witness);
    spongefish_prover_ch.state.narg_string().to_vec()
}

/// Non-interactive verifier for an IOR: creates a sponge channel, runs
/// `IR::verify`, checks EOF, returns the **target instance**.
pub fn verify_reduction<'a, IR>(
    session: [u8; 64],
    instance: &IR::SourceInstance,
    proof: &'a [u8],
) -> ia_core::VerificationResult<IR::TargetInstance>
where
    IR: ReduceVerify<SpongeVerifier<'a>>,
    IR::SourceInstance: Encoding,
{
    let domsep = DomainSeparator::new(IR::protocol_id())
        .session(session)
        .instance(instance);

    let mut spongefish_verifier_ch = SpongeVerifier {
        state: domsep.std_verifier(proof),
    };
    let target = IR::verify(&mut spongefish_verifier_ch, instance)?;
    spongefish_verifier_ch
        .state
        .check_eof()
        .map_err(|_| ia_core::VerificationError)?;
    Ok(target)
}
