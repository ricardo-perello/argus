//! DSFS non-interactive prove/verify entry points.

extern crate alloc;

use alloc::vec::Vec;

use rand_core::RngCore;

use ia_core::{
    Prove, ReduceProve, ReduceVerify, Verify,
};
use spongefish::{DomainSeparator, Encoding};

use crate::channel::{SpongeProver, SpongeVerifier};
use crate::params::Keccak;

/// Non-interactive prover with explicit salt length.
pub fn prove_with_salt<IA, const SALT_LEN: usize>(
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

    let mut spongefish_prover_ch = SpongeProver::new(domsep.to_prover(Keccak::default()));
    let mut salt = [0u8; SALT_LEN];
    spongefish_prover_ch.state.rng().fill_bytes(&mut salt);
    spongefish_prover_ch.state.prover_message(&salt);
    IA::prove(&mut spongefish_prover_ch, instance, witness);
    spongefish_prover_ch.narg_string().to_vec()
}

/// Non-interactive prover with default `SALT_LEN = 0`.
pub fn prove<IA>(
    session: [u8; 64],
    instance: &IA::Instance,
    witness: &IA::Witness,
) -> Vec<u8>
where
    IA: Prove<SpongeProver>,
    IA::Instance: Encoding,
{
    prove_with_salt::<IA, 0>(session, instance, witness)
}

/// Non-interactive verifier with explicit salt length.
pub fn verify_with_salt<'a, IA, const SALT_LEN: usize>(
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

    let mut spongefish_verifier_ch =
        SpongeVerifier::new(domsep.to_verifier(Keccak::default(), proof));
    let _salt: [u8; SALT_LEN] = spongefish_verifier_ch
        .state
        .prover_message()
        .map_err(|_| ia_core::VerificationError)?;
    IA::verify(&mut spongefish_verifier_ch, instance)?;
    spongefish_verifier_ch
        .state
        .check_eof()
        .map_err(|_| ia_core::VerificationError)
}

/// Non-interactive verifier with default `SALT_LEN = 0`.
pub fn verify<'a, IA>(
    session: [u8; 64],
    instance: &IA::Instance,
    proof: &'a [u8],
) -> ia_core::VerificationResult<()>
where
    IA: Verify<SpongeVerifier<'a>>,
    IA::Instance: Encoding,
{
    verify_with_salt::<IA, 0>(session, instance, proof)
}

/// Non-interactive prover for an IOR with explicit salt length.
pub fn prove_reduction_with_salt<IR, const SALT_LEN: usize>(
    session: [u8; 64],
    instance: &IR::SourceInstance,
    witness: &IR::SourceWitness,
) -> Vec<u8>
where
    IR: ReduceProve<SpongeProver>,
    IR::SourceInstance: Encoding,
{
    let domsep = DomainSeparator::new(IR::protocol_id())
        .session(session)
        .instance(instance);

    let mut spongefish_prover_ch = SpongeProver::new(domsep.to_prover(Keccak::default()));
    let mut salt = [0u8; SALT_LEN];
    spongefish_prover_ch.state.rng().fill_bytes(&mut salt);
    spongefish_prover_ch.state.prover_message(&salt);
    let (_target_instance, _target_witness) = IR::prove(&mut spongefish_prover_ch, instance, witness);
    spongefish_prover_ch.narg_string().to_vec()
}

/// Non-interactive prover for an IOR with default `SALT_LEN = 0`.
pub fn prove_reduction<IR>(
    session: [u8; 64],
    instance: &IR::SourceInstance,
    witness: &IR::SourceWitness,
) -> Vec<u8>
where
    IR: ReduceProve<SpongeProver>,
    IR::SourceInstance: Encoding,
{
    prove_reduction_with_salt::<IR, 0>(session, instance, witness)
}

/// Non-interactive verifier for an IOR with explicit salt length.
pub fn verify_reduction_with_salt<'a, IR, const SALT_LEN: usize>(
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

    let mut spongefish_verifier_ch =
        SpongeVerifier::new(domsep.to_verifier(Keccak::default(), proof));
    let _salt: [u8; SALT_LEN] = spongefish_verifier_ch
        .state
        .prover_message()
        .map_err(|_| ia_core::VerificationError)?;
    let target = IR::verify(&mut spongefish_verifier_ch, instance)?;
    spongefish_verifier_ch
        .state
        .check_eof()
        .map_err(|_| ia_core::VerificationError)?;
    Ok(target)
}

/// Non-interactive verifier for an IOR with default `SALT_LEN = 0`.
pub fn verify_reduction<'a, IR>(
    session: [u8; 64],
    instance: &IR::SourceInstance,
    proof: &'a [u8],
) -> ia_core::VerificationResult<IR::TargetInstance>
where
    IR: ReduceVerify<SpongeVerifier<'a>>,
    IR::SourceInstance: Encoding,
{
    verify_reduction_with_salt::<IR, 0>(session, instance, proof)
}
