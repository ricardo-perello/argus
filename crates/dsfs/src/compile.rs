//! DSFS non-interactive prove/verify entry points.

extern crate alloc;

use alloc::vec::Vec;

use rand_core::RngCore;

use ia_core::{Prove, ReduceProve, ReduceVerify, Verify};
use spongefish::{protocol_id as spongefish_protocol_id, DomainSeparator, DuplexSpongeInterface, Encoding};

use crate::channel::{SpongeProver, SpongeVerifier};
use crate::params::Keccak;

/// Byte-oriented duplex sponge (`U = u8`), matching Keccak and spongefish `StdHash` / SHAKE128.
pub trait ByteDuplexSponge: DuplexSpongeInterface<U = u8> {}

impl<T: DuplexSpongeInterface<U = u8>> ByteDuplexSponge for T {}

/// DSFS-level 64-byte protocol identifier for the compiled non-interactive argument.
///
/// This tags the *NARG format* (DSFS[IA] with salt length and sponge `H`), not just the
/// underlying interactive argument. Different salts or sponge choices get distinct ids,
/// while `StdHash` + `SALT_LEN = 0` can still be aligned explicitly with external schemes
/// (e.g. σ-proofs `Nizk`) by choosing a compatible label here.
fn dsfs_protocol_id<IA, H, const SALT_LEN: usize>() -> [u8; 64]
where
    H: ByteDuplexSponge,
    IA: Prove<SpongeProver<H>>,
{
    // Keep this ASCII and <= 64 bytes; type names are long, so we rely on them alone for now.
    // If we ever need exact cross-language alignment, we can specialize the label per IA/H pair.
    spongefish_protocol_id(core::format_args!(
        "DSFS[{};salt={};sponge={}]",
        core::any::type_name::<IA>(),
        SALT_LEN,
        core::any::type_name::<H>(),
    ))
}

/// Non-interactive prover with explicit salt length and duplex sponge `H`.
pub fn prove_with_sponge_and_salt<IA, H, const SALT_LEN: usize>(
    sponge: H,
    session: [u8; 64],
    instance: &IA::Instance,
    witness: &IA::Witness,
) -> Vec<u8>
where
    H: ByteDuplexSponge,
    IA: Prove<SpongeProver<H>>,
    IA::Instance: Encoding<[H::U]>,
    [u8; 64]: Encoding<[H::U]>,
    [u8; SALT_LEN]: Encoding<[H::U]>,
{
    let domsep = DomainSeparator::new(dsfs_protocol_id::<IA, H, SALT_LEN>())
        .session(session)
        .instance(instance);

    let mut spongefish_prover_ch = SpongeProver::new(domsep.to_prover(sponge));
    let mut salt = [0u8; SALT_LEN];
    spongefish_prover_ch.state.rng().fill_bytes(&mut salt);
    spongefish_prover_ch.state.prover_message(&salt);
    IA::prove(&mut spongefish_prover_ch, instance, witness);
    spongefish_prover_ch.narg_string().to_vec()
}

/// Non-interactive prover with default salt (`SALT_LEN = 0`).
pub fn prove_with_sponge<IA, H>(
    sponge: H,
    session: [u8; 64],
    instance: &IA::Instance,
    witness: &IA::Witness,
) -> Vec<u8>
where
    H: ByteDuplexSponge,
    IA: Prove<SpongeProver<H>>,
    IA::Instance: Encoding<[H::U]>,
    [u8; 64]: Encoding<[H::U]>,
{
    prove_with_sponge_and_salt::<IA, H, 0>(sponge, session, instance, witness)
}

/// Non-interactive prover with explicit salt length (standard Keccak duplex).
pub fn prove_with_salt<IA, const SALT_LEN: usize>(
    session: [u8; 64],
    instance: &IA::Instance,
    witness: &IA::Witness,
) -> Vec<u8>
where
    IA: Prove<SpongeProver>,
    IA::Instance: Encoding,
{
    prove_with_sponge_and_salt::<IA, Keccak, SALT_LEN>(
        Keccak::default(),
        session,
        instance,
        witness,
    )
}

/// Non-interactive prover with default `SALT_LEN = 0`.
pub fn prove<IA>(session: [u8; 64], instance: &IA::Instance, witness: &IA::Witness) -> Vec<u8>
where
    IA: Prove<SpongeProver>,
    IA::Instance: Encoding,
{
    prove_with_salt::<IA, 0>(session, instance, witness)
}

/// Non-interactive verifier with explicit salt length and duplex sponge `H`.
pub fn verify_with_sponge_and_salt<'a, IA, H, const SALT_LEN: usize>(
    sponge: H,
    session: [u8; 64],
    instance: &IA::Instance,
    proof: &'a [u8],
) -> ia_core::VerificationResult<()>
where
    H: ByteDuplexSponge,
    IA: Verify<SpongeVerifier<'a, H>>,
    IA::Instance: Encoding<[H::U]>,
    [u8; 64]: Encoding<[H::U]>,
    [u8; SALT_LEN]: Encoding<[H::U]> + spongefish::NargDeserialize,
{
    let domsep = DomainSeparator::new(IA::protocol_id())
        .session(session)
        .instance(instance);

    let mut spongefish_verifier_ch = SpongeVerifier::new(domsep.to_verifier(sponge, proof));
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

/// Non-interactive verifier with default salt (`SALT_LEN = 0`).
pub fn verify_with_sponge<'a, IA, H>(
    sponge: H,
    session: [u8; 64],
    instance: &IA::Instance,
    proof: &'a [u8],
) -> ia_core::VerificationResult<()>
where
    H: ByteDuplexSponge,
    IA: Verify<SpongeVerifier<'a, H>>,
    IA::Instance: Encoding<[H::U]>,
    [u8; 64]: Encoding<[H::U]>,
    [u8; 0]: Encoding<[H::U]> + spongefish::NargDeserialize,
{
    verify_with_sponge_and_salt::<IA, H, 0>(sponge, session, instance, proof)
}

/// Non-interactive verifier with explicit salt length (standard Keccak duplex).
pub fn verify_with_salt<'a, IA, const SALT_LEN: usize>(
    session: [u8; 64],
    instance: &IA::Instance,
    proof: &'a [u8],
) -> ia_core::VerificationResult<()>
where
    IA: Verify<SpongeVerifier<'a>>,
    IA::Instance: Encoding,
    [u8; SALT_LEN]: spongefish::NargDeserialize,
{
    verify_with_sponge_and_salt::<IA, Keccak, SALT_LEN>(Keccak::default(), session, instance, proof)
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

/// Non-interactive prover for an IOR with explicit salt length and sponge `H`.
pub fn prove_reduction_with_sponge_and_salt<IR, H, const SALT_LEN: usize>(
    sponge: H,
    session: [u8; 64],
    instance: &IR::SourceInstance,
    witness: &IR::SourceWitness,
) -> Vec<u8>
where
    H: ByteDuplexSponge,
    IR: ReduceProve<SpongeProver<H>>,
    IR::SourceInstance: Encoding<[H::U]>,
    [u8; 64]: Encoding<[H::U]>,
    [u8; SALT_LEN]: Encoding<[H::U]>,
{
    let domsep = DomainSeparator::new(IR::protocol_id())
        .session(session)
        .instance(instance);

    let mut spongefish_prover_ch = SpongeProver::new(domsep.to_prover(sponge));
    let mut salt = [0u8; SALT_LEN];
    spongefish_prover_ch.state.rng().fill_bytes(&mut salt);
    spongefish_prover_ch.state.prover_message(&salt);
    let (_target_instance, _target_witness) =
        IR::prove(&mut spongefish_prover_ch, instance, witness);
    spongefish_prover_ch.narg_string().to_vec()
}

pub fn prove_reduction_with_sponge<IR, H>(
    sponge: H,
    session: [u8; 64],
    instance: &IR::SourceInstance,
    witness: &IR::SourceWitness,
) -> Vec<u8>
where
    H: ByteDuplexSponge,
    IR: ReduceProve<SpongeProver<H>>,
    IR::SourceInstance: Encoding<[H::U]>,
    [u8; 64]: Encoding<[H::U]>,
{
    prove_reduction_with_sponge_and_salt::<IR, H, 0>(sponge, session, instance, witness)
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
    prove_reduction_with_sponge_and_salt::<IR, Keccak, SALT_LEN>(
        Keccak::default(),
        session,
        instance,
        witness,
    )
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

/// Non-interactive verifier for an IOR with explicit salt length and sponge `H`.
pub fn verify_reduction_with_sponge_and_salt<'a, IR, H, const SALT_LEN: usize>(
    sponge: H,
    session: [u8; 64],
    instance: &IR::SourceInstance,
    proof: &'a [u8],
) -> ia_core::VerificationResult<IR::TargetInstance>
where
    H: ByteDuplexSponge,
    IR: ReduceVerify<SpongeVerifier<'a, H>>,
    IR::SourceInstance: Encoding<[H::U]>,
    [u8; 64]: Encoding<[H::U]>,
    [u8; SALT_LEN]: Encoding<[H::U]> + spongefish::NargDeserialize,
{
    let domsep = DomainSeparator::new(IR::protocol_id())
        .session(session)
        .instance(instance);

    let mut spongefish_verifier_ch = SpongeVerifier::new(domsep.to_verifier(sponge, proof));
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

pub fn verify_reduction_with_sponge<'a, IR, H>(
    sponge: H,
    session: [u8; 64],
    instance: &IR::SourceInstance,
    proof: &'a [u8],
) -> ia_core::VerificationResult<IR::TargetInstance>
where
    H: ByteDuplexSponge,
    IR: ReduceVerify<SpongeVerifier<'a, H>>,
    IR::SourceInstance: Encoding<[H::U]>,
    [u8; 64]: Encoding<[H::U]>,
    [u8; 0]: Encoding<[H::U]> + spongefish::NargDeserialize,
{
    verify_reduction_with_sponge_and_salt::<IR, H, 0>(sponge, session, instance, proof)
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
    [u8; SALT_LEN]: spongefish::NargDeserialize,
{
    verify_reduction_with_sponge_and_salt::<IR, Keccak, SALT_LEN>(
        Keccak::default(),
        session,
        instance,
        proof,
    )
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
