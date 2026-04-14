//! DSFS non-interactive prove/verify entry points.

extern crate alloc;

use alloc::vec::Vec;

use rand_core::RngCore;

use ia_core::{InteractiveArgument, InteractiveReduction};
use spongefish::{DomainSeparator, DuplexSpongeInterface, Encoding};

use crate::channel::{SpongeProver, SpongeVerifier};
use crate::params::{Keccak, SpongeInfo};

/// Byte-oriented duplex sponge (`U = u8`), matching Keccak and spongefish `StdHash` / SHAKE128.
pub trait ByteDuplexSponge: DuplexSpongeInterface<U = u8> {}

impl<T: DuplexSpongeInterface<U = u8>> ByteDuplexSponge for T {}

/// Non-interactive prover with explicit salt length and duplex sponge `H`.
#[inline]
pub fn prove_with_sponge_and_salt<IA, H, S, const SALT_LEN: usize>(
    ia: &IA,
    sponge: H,
    session: &S,
    instance: &IA::Instance,
    witness: &IA::Witness,
) -> Vec<u8>
where
    H: SpongeInfo,
    IA: InteractiveArgument,
    S: Encoding<[u8]>,
    IA::Instance: Encoding<[H::U]>,
    [u8; SALT_LEN]: Encoding<[H::U]>,
{
    let session_bytes = session.encode();
    let domsep = DomainSeparator::derive(
        ia.protocol_id().as_ref(),
        H::SPONGE_INFO,
        session_bytes.as_ref(),
    )
    .instance(instance);

    let mut spongefish_prover_ch = SpongeProver::new(domsep.to_prover(sponge));
    let mut salt = [0u8; SALT_LEN];
    spongefish_prover_ch.state.rng().fill_bytes(&mut salt);
    spongefish_prover_ch.state.prover_message(&salt);
    ia.prove(&mut spongefish_prover_ch, instance, witness);
    spongefish_prover_ch.narg_string().to_vec()
}

/// Non-interactive prover with default salt (`SALT_LEN = 0`).
#[inline(always)]
pub fn prove_with_sponge<IA, H, S>(
    ia: &IA,
    sponge: H,
    session: &S,
    instance: &IA::Instance,
    witness: &IA::Witness,
) -> Vec<u8>
where
    H: SpongeInfo,
    IA: InteractiveArgument,
    S: Encoding<[u8]>,
    IA::Instance: Encoding<[H::U]>,
{
    prove_with_sponge_and_salt::<IA, H, S, 0>(ia, sponge, session, instance, witness)
}

/// Non-interactive prover with explicit salt length (standard Keccak duplex).
#[inline(always)]
pub fn prove_with_salt<IA, S, const SALT_LEN: usize>(
    ia: &IA,
    session: &S,
    instance: &IA::Instance,
    witness: &IA::Witness,
) -> Vec<u8>
where
    IA: InteractiveArgument,
    S: Encoding<[u8]>,
    IA::Instance: Encoding,
{
    prove_with_sponge_and_salt::<IA, Keccak, S, SALT_LEN>(
        ia,
        Keccak::default(),
        session,
        instance,
        witness,
    )
}

/// Non-interactive prover with default `SALT_LEN = 0`.
#[inline(always)]
pub fn prove<IA, S>(
    ia: &IA,
    session: &S,
    instance: &IA::Instance,
    witness: &IA::Witness,
) -> Vec<u8>
where
    IA: InteractiveArgument,
    S: Encoding<[u8]>,
    IA::Instance: Encoding,
{
    prove_with_salt::<IA, S, 0>(ia, session, instance, witness)
}

/// Non-interactive verifier with explicit salt length and duplex sponge `H`.
pub fn verify_with_sponge_and_salt<'a, IA, H, S, const SALT_LEN: usize>(
    ia: &IA,
    sponge: H,
    session: &S,
    instance: &IA::Instance,
    proof: &'a [u8],
) -> ia_core::VerificationResult<()>
where
    H: SpongeInfo,
    IA: InteractiveArgument,
    S: Encoding<[u8]>,
    IA::Instance: Encoding<[H::U]>,
    [u8; SALT_LEN]: Encoding<[H::U]> + spongefish::NargDeserialize,
{
    let session_bytes = session.encode();
    let domsep = DomainSeparator::derive(
        ia.protocol_id().as_ref(),
        H::SPONGE_INFO,
        session_bytes.as_ref(),
    )
    .instance(instance);

    let mut spongefish_verifier_ch = SpongeVerifier::new(domsep.to_verifier(sponge, proof));
    let _salt: [u8; SALT_LEN] = spongefish_verifier_ch
        .state
        .prover_message()
        .map_err(|_| ia_core::VerificationError)?;
    ia.verify(&mut spongefish_verifier_ch, instance)?;
    spongefish_verifier_ch
        .state
        .check_eof()
        .map_err(|_| ia_core::VerificationError)
}

/// Non-interactive verifier with default salt (`SALT_LEN = 0`).
pub fn verify_with_sponge<'a, IA, H, S>(
    ia: &IA,
    sponge: H,
    session: &S,
    instance: &IA::Instance,
    proof: &'a [u8],
) -> ia_core::VerificationResult<()>
where
    H: SpongeInfo,
    IA: InteractiveArgument,
    S: Encoding<[u8]>,
    IA::Instance: Encoding<[H::U]>,
    [u8; 0]: Encoding<[H::U]> + spongefish::NargDeserialize,
{
    verify_with_sponge_and_salt::<IA, H, S, 0>(ia, sponge, session, instance, proof)
}

/// Non-interactive verifier with explicit salt length (standard Keccak duplex).
pub fn verify_with_salt<'a, IA, S, const SALT_LEN: usize>(
    ia: &IA,
    session: &S,
    instance: &IA::Instance,
    proof: &'a [u8],
) -> ia_core::VerificationResult<()>
where
    IA: InteractiveArgument,
    S: Encoding<[u8]>,
    IA::Instance: Encoding,
    [u8; SALT_LEN]: spongefish::NargDeserialize,
{
    verify_with_sponge_and_salt::<IA, Keccak, S, SALT_LEN>(
        ia,
        Keccak::default(),
        session,
        instance,
        proof,
    )
}

/// Non-interactive verifier with default `SALT_LEN = 0`.
pub fn verify<'a, IA, S>(
    ia: &IA,
    session: &S,
    instance: &IA::Instance,
    proof: &'a [u8],
) -> ia_core::VerificationResult<()>
where
    IA: InteractiveArgument,
    S: Encoding<[u8]>,
    IA::Instance: Encoding,
{
    verify_with_salt::<IA, S, 0>(ia, session, instance, proof)
}

/// Non-interactive prover for an IOR with explicit salt length and sponge `H`.
pub fn prove_reduction_with_sponge_and_salt<IR, H, S, const SALT_LEN: usize>(
    ir: &IR,
    sponge: H,
    session: &S,
    instance: &IR::SourceInstance,
    witness: &IR::SourceWitness,
) -> Vec<u8>
where
    H: SpongeInfo,
    IR: InteractiveReduction,
    S: Encoding<[u8]>,
    IR::SourceInstance: Encoding<[H::U]>,
    [u8; SALT_LEN]: Encoding<[H::U]>,
{
    let session_bytes = session.encode();
    let domsep = DomainSeparator::derive(
        ir.protocol_id().as_ref(),
        H::SPONGE_INFO,
        session_bytes.as_ref(),
    )
    .instance(instance);

    let mut spongefish_prover_ch = SpongeProver::new(domsep.to_prover(sponge));
    let mut salt = [0u8; SALT_LEN];
    spongefish_prover_ch.state.rng().fill_bytes(&mut salt);
    spongefish_prover_ch.state.prover_message(&salt);
    let (_target_instance, _target_witness) =
        ir.prove(&mut spongefish_prover_ch, instance, witness);
    spongefish_prover_ch.narg_string().to_vec()
}

pub fn prove_reduction_with_sponge<IR, H, S>(
    ir: &IR,
    sponge: H,
    session: &S,
    instance: &IR::SourceInstance,
    witness: &IR::SourceWitness,
) -> Vec<u8>
where
    H: SpongeInfo,
    IR: InteractiveReduction,
    S: Encoding<[u8]>,
    IR::SourceInstance: Encoding<[H::U]>,
{
    prove_reduction_with_sponge_and_salt::<IR, H, S, 0>(ir, sponge, session, instance, witness)
}

/// Non-interactive prover for an IOR with explicit salt length.
pub fn prove_reduction_with_salt<IR, S, const SALT_LEN: usize>(
    ir: &IR,
    session: &S,
    instance: &IR::SourceInstance,
    witness: &IR::SourceWitness,
) -> Vec<u8>
where
    IR: InteractiveReduction,
    S: Encoding<[u8]>,
    IR::SourceInstance: Encoding,
{
    prove_reduction_with_sponge_and_salt::<IR, Keccak, S, SALT_LEN>(
        ir,
        Keccak::default(),
        session,
        instance,
        witness,
    )
}

/// Non-interactive prover for an IOR with default `SALT_LEN = 0`.
pub fn prove_reduction<IR, S>(
    ir: &IR,
    session: &S,
    instance: &IR::SourceInstance,
    witness: &IR::SourceWitness,
) -> Vec<u8>
where
    IR: InteractiveReduction,
    S: Encoding<[u8]>,
    IR::SourceInstance: Encoding,
{
    prove_reduction_with_salt::<IR, S, 0>(ir, session, instance, witness)
}

/// Non-interactive verifier for an IOR with explicit salt length and sponge `H`.
pub fn verify_reduction_with_sponge_and_salt<'a, IR, H, S, const SALT_LEN: usize>(
    ir: &IR,
    sponge: H,
    session: &S,
    instance: &IR::SourceInstance,
    proof: &'a [u8],
) -> ia_core::VerificationResult<IR::TargetInstance>
where
    H: SpongeInfo,
    IR: InteractiveReduction,
    S: Encoding<[u8]>,
    IR::SourceInstance: Encoding<[H::U]>,
    [u8; SALT_LEN]: Encoding<[H::U]> + spongefish::NargDeserialize,
{
    let session_bytes = session.encode();
    let domsep = DomainSeparator::derive(
        ir.protocol_id().as_ref(),
        H::SPONGE_INFO,
        session_bytes.as_ref(),
    )
    .instance(instance);

    let mut spongefish_verifier_ch = SpongeVerifier::new(domsep.to_verifier(sponge, proof));
    let _salt: [u8; SALT_LEN] = spongefish_verifier_ch
        .state
        .prover_message()
        .map_err(|_| ia_core::VerificationError)?;
    let target = ir.verify(&mut spongefish_verifier_ch, instance)?;
    spongefish_verifier_ch
        .state
        .check_eof()
        .map_err(|_| ia_core::VerificationError)?;
    Ok(target)
}

pub fn verify_reduction_with_sponge<'a, IR, H, S>(
    ir: &IR,
    sponge: H,
    session: &S,
    instance: &IR::SourceInstance,
    proof: &'a [u8],
) -> ia_core::VerificationResult<IR::TargetInstance>
where
    H: SpongeInfo,
    IR: InteractiveReduction,
    S: Encoding<[u8]>,
    IR::SourceInstance: Encoding<[H::U]>,
    [u8; 0]: Encoding<[H::U]> + spongefish::NargDeserialize,
{
    verify_reduction_with_sponge_and_salt::<IR, H, S, 0>(ir, sponge, session, instance, proof)
}

/// Non-interactive verifier for an IOR with explicit salt length.
pub fn verify_reduction_with_salt<'a, IR, S, const SALT_LEN: usize>(
    ir: &IR,
    session: &S,
    instance: &IR::SourceInstance,
    proof: &'a [u8],
) -> ia_core::VerificationResult<IR::TargetInstance>
where
    IR: InteractiveReduction,
    S: Encoding<[u8]>,
    IR::SourceInstance: Encoding,
    [u8; SALT_LEN]: spongefish::NargDeserialize,
{
    verify_reduction_with_sponge_and_salt::<IR, Keccak, S, SALT_LEN>(
        ir,
        Keccak::default(),
        session,
        instance,
        proof,
    )
}

/// Non-interactive verifier for an IOR with default `SALT_LEN = 0`.
pub fn verify_reduction<'a, IR, S>(
    ir: &IR,
    session: &S,
    instance: &IR::SourceInstance,
    proof: &'a [u8],
) -> ia_core::VerificationResult<IR::TargetInstance>
where
    IR: InteractiveReduction,
    S: Encoding<[u8]>,
    IR::SourceInstance: Encoding,
{
    verify_reduction_with_salt::<IR, S, 0>(ir, session, instance, proof)
}
