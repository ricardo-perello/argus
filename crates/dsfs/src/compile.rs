//! DSFS non-interactive prove/verify entry points.

extern crate alloc;

use alloc::vec::Vec;

use rand_core::RngCore;

use ia_core::{InteractiveArgument, InteractiveReduction};
use spongefish::{DomainSeparator, DuplexSpongeInterface, Encoding};

use crate::channel::{SpongeProver, SpongeVerifier};
use crate::params::{Keccak, SpongeTag};

/// Byte-oriented duplex sponge (`U = u8`), matching Keccak and spongefish `StdHash` / SHAKE128.
pub trait ByteDuplexSponge: DuplexSpongeInterface<U = u8> {}

impl<T: DuplexSpongeInterface<U = u8>> ByteDuplexSponge for T {}

/// DSFS-level 64-byte protocol identifier for the compiled non-interactive argument.
///
/// Tags the full NARG format — not just the underlying IA — by hashing together:
///   - `IA::protocol_id()` (the interactive argument's identity)
///   - the sponge type name (encodes the hash function choice)
///   - `SALT_LEN` (encodes the salt policy)
///
/// Different sponge choices or salt lengths produce distinct domain separators even
/// for the same underlying IA, preventing cross-format proof confusion.
/// Build the full 64-byte DSFS domain separator: `ia_id[32] || sponge_tag[32]`.
///
/// The IA/IR supplies a 32-byte human-readable label (`protocol_id()`); the
/// sponge type supplies a 32-byte tag encoding the hash-function choice.
/// Concatenating the two gives a domain separator that uniquely identifies
/// both the protocol and its compiled NARG format — matching sigma-proofs'
/// convention of embedding the ciphersuite in the ASCII label.
fn build_domain_sep(ia_id: [u8; 32], sponge_tag: [u8; 32]) -> [u8; 64] {
    let mut id = [0u8; 64];
    id[..32].copy_from_slice(&ia_id);
    id[32..].copy_from_slice(&sponge_tag);
    id
}

/// Stage 1 temporary: compress a variable-length IA/IR protocol id into 32 bytes
/// via a domain-separated BLAKE3 KDF. Removed in Stage 3 once the spongefish
/// `DomainSeparator::derive` API lands and can take the raw slice directly.
fn compact_protocol_id(raw: &[u8]) -> [u8; 32] {
    blake3::derive_key("argus/dsfs/v1/ia-protocol-id-compact", raw)
}

fn dsfs_protocol_id<IA, H>(ia: &IA) -> [u8; 64]
where
    H: SpongeTag,
    IA: InteractiveArgument,
{
    build_domain_sep(compact_protocol_id(ia.protocol_id().as_ref()), H::TAG)
}

fn dsfs_reduction_protocol_id<IR, H>(ir: &IR) -> [u8; 64]
where
    H: SpongeTag,
    IR: InteractiveReduction,
{
    build_domain_sep(compact_protocol_id(ir.protocol_id().as_ref()), H::TAG)
}


/// Non-interactive prover with explicit salt length and duplex sponge `H`.
#[inline]
pub fn prove_with_sponge_and_salt<IA, H, const SALT_LEN: usize>(
    ia: &IA,
    sponge: H,
    session: [u8; 64],
    instance: &IA::Instance,
    witness: &IA::Witness,
) -> Vec<u8>
where
    H: SpongeTag,
    IA: InteractiveArgument,
    IA::Instance: Encoding<[H::U]>,
    [u8; 64]: Encoding<[H::U]>,
    [u8; SALT_LEN]: Encoding<[H::U]>,
{
    let domsep = DomainSeparator::new(dsfs_protocol_id::<IA, H>(ia))
        .session(session)
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
pub fn prove_with_sponge<IA, H>(
    ia: &IA,
    sponge: H,
    session: [u8; 64],
    instance: &IA::Instance,
    witness: &IA::Witness,
) -> Vec<u8>
where
    H: SpongeTag,
    IA: InteractiveArgument,
    IA::Instance: Encoding<[H::U]>,
    [u8; 64]: Encoding<[H::U]>,
{
    prove_with_sponge_and_salt::<IA, H, 0>(ia, sponge, session, instance, witness)
}

/// Non-interactive prover with explicit salt length (standard Keccak duplex).
#[inline(always)]
pub fn prove_with_salt<IA, const SALT_LEN: usize>(
    ia: &IA,
    session: [u8; 64],
    instance: &IA::Instance,
    witness: &IA::Witness,
) -> Vec<u8>
where
    IA: InteractiveArgument,
    IA::Instance: Encoding,
{
    prove_with_sponge_and_salt::<IA, Keccak, SALT_LEN>(
        ia,
        Keccak::default(),
        session,
        instance,
        witness,
    )
}

/// Non-interactive prover with default `SALT_LEN = 0`.
#[inline(always)]
pub fn prove<IA>(
    ia: &IA,
    session: [u8; 64],
    instance: &IA::Instance,
    witness: &IA::Witness,
) -> Vec<u8>
where
    IA: InteractiveArgument,
    IA::Instance: Encoding,
{
    prove_with_salt::<IA, 0>(ia, session, instance, witness)
}

/// Non-interactive verifier with explicit salt length and duplex sponge `H`.
pub fn verify_with_sponge_and_salt<'a, IA, H, const SALT_LEN: usize>(
    ia: &IA,
    sponge: H,
    session: [u8; 64],
    instance: &IA::Instance,
    proof: &'a [u8],
) -> ia_core::VerificationResult<()>
where
    H: SpongeTag,
    IA: InteractiveArgument,
    IA::Instance: Encoding<[H::U]>,
    [u8; 64]: Encoding<[H::U]>,
    [u8; SALT_LEN]: Encoding<[H::U]> + spongefish::NargDeserialize,
{
    let domsep = DomainSeparator::new(dsfs_protocol_id::<IA, H>(ia))
        .session(session)
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
pub fn verify_with_sponge<'a, IA, H>(
    ia: &IA,
    sponge: H,
    session: [u8; 64],
    instance: &IA::Instance,
    proof: &'a [u8],
) -> ia_core::VerificationResult<()>
where
    H: SpongeTag,
    IA: InteractiveArgument,
    IA::Instance: Encoding<[H::U]>,
    [u8; 64]: Encoding<[H::U]>,
    [u8; 0]: Encoding<[H::U]> + spongefish::NargDeserialize,
{
    verify_with_sponge_and_salt::<IA, H, 0>(ia, sponge, session, instance, proof)
}

/// Non-interactive verifier with explicit salt length (standard Keccak duplex).
pub fn verify_with_salt<'a, IA, const SALT_LEN: usize>(
    ia: &IA,
    session: [u8; 64],
    instance: &IA::Instance,
    proof: &'a [u8],
) -> ia_core::VerificationResult<()>
where
    IA: InteractiveArgument,
    IA::Instance: Encoding,
    [u8; SALT_LEN]: spongefish::NargDeserialize,
{
    verify_with_sponge_and_salt::<IA, Keccak, SALT_LEN>(
        ia,
        Keccak::default(),
        session,
        instance,
        proof,
    )
}

/// Non-interactive verifier with default `SALT_LEN = 0`.
pub fn verify<'a, IA>(
    ia: &IA,
    session: [u8; 64],
    instance: &IA::Instance,
    proof: &'a [u8],
) -> ia_core::VerificationResult<()>
where
    IA: InteractiveArgument,
    IA::Instance: Encoding,
{
    verify_with_salt::<IA, 0>(ia, session, instance, proof)
}

/// Non-interactive prover for an IOR with explicit salt length and sponge `H`.
pub fn prove_reduction_with_sponge_and_salt<IR, H, const SALT_LEN: usize>(
    ir: &IR,
    sponge: H,
    session: [u8; 64],
    instance: &IR::SourceInstance,
    witness: &IR::SourceWitness,
) -> Vec<u8>
where
    H: SpongeTag,
    IR: InteractiveReduction,
    IR::SourceInstance: Encoding<[H::U]>,
    [u8; 64]: Encoding<[H::U]>,
    [u8; SALT_LEN]: Encoding<[H::U]>,
{
    let domsep = DomainSeparator::new(dsfs_reduction_protocol_id::<IR, H>(ir))
        .session(session)
        .instance(instance);

    let mut spongefish_prover_ch = SpongeProver::new(domsep.to_prover(sponge));
    let mut salt = [0u8; SALT_LEN];
    spongefish_prover_ch.state.rng().fill_bytes(&mut salt);
    spongefish_prover_ch.state.prover_message(&salt);
    let (_target_instance, _target_witness) =
        ir.prove(&mut spongefish_prover_ch, instance, witness);
    spongefish_prover_ch.narg_string().to_vec()
}

pub fn prove_reduction_with_sponge<IR, H>(
    ir: &IR,
    sponge: H,
    session: [u8; 64],
    instance: &IR::SourceInstance,
    witness: &IR::SourceWitness,
) -> Vec<u8>
where
    H: SpongeTag,
    IR: InteractiveReduction,
    IR::SourceInstance: Encoding<[H::U]>,
    [u8; 64]: Encoding<[H::U]>,
{
    prove_reduction_with_sponge_and_salt::<IR, H, 0>(ir, sponge, session, instance, witness)
}

/// Non-interactive prover for an IOR with explicit salt length.
pub fn prove_reduction_with_salt<IR, const SALT_LEN: usize>(
    ir: &IR,
    session: [u8; 64],
    instance: &IR::SourceInstance,
    witness: &IR::SourceWitness,
) -> Vec<u8>
where
    IR: InteractiveReduction,
    IR::SourceInstance: Encoding,
{
    prove_reduction_with_sponge_and_salt::<IR, Keccak, SALT_LEN>(
        ir,
        Keccak::default(),
        session,
        instance,
        witness,
    )
}

/// Non-interactive prover for an IOR with default `SALT_LEN = 0`.
pub fn prove_reduction<IR>(
    ir: &IR,
    session: [u8; 64],
    instance: &IR::SourceInstance,
    witness: &IR::SourceWitness,
) -> Vec<u8>
where
    IR: InteractiveReduction,
    IR::SourceInstance: Encoding,
{
    prove_reduction_with_salt::<IR, 0>(ir, session, instance, witness)
}

/// Non-interactive verifier for an IOR with explicit salt length and sponge `H`.
pub fn verify_reduction_with_sponge_and_salt<'a, IR, H, const SALT_LEN: usize>(
    ir: &IR,
    sponge: H,
    session: [u8; 64],
    instance: &IR::SourceInstance,
    proof: &'a [u8],
) -> ia_core::VerificationResult<IR::TargetInstance>
where
    H: SpongeTag,
    IR: InteractiveReduction,
    IR::SourceInstance: Encoding<[H::U]>,
    [u8; 64]: Encoding<[H::U]>,
    [u8; SALT_LEN]: Encoding<[H::U]> + spongefish::NargDeserialize,
{
    let domsep = DomainSeparator::new(dsfs_reduction_protocol_id::<IR, H>(ir))
        .session(session)
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

pub fn verify_reduction_with_sponge<'a, IR, H>(
    ir: &IR,
    sponge: H,
    session: [u8; 64],
    instance: &IR::SourceInstance,
    proof: &'a [u8],
) -> ia_core::VerificationResult<IR::TargetInstance>
where
    H: SpongeTag,
    IR: InteractiveReduction,
    IR::SourceInstance: Encoding<[H::U]>,
    [u8; 64]: Encoding<[H::U]>,
    [u8; 0]: Encoding<[H::U]> + spongefish::NargDeserialize,
{
    verify_reduction_with_sponge_and_salt::<IR, H, 0>(ir, sponge, session, instance, proof)
}

/// Non-interactive verifier for an IOR with explicit salt length.
pub fn verify_reduction_with_salt<'a, IR, const SALT_LEN: usize>(
    ir: &IR,
    session: [u8; 64],
    instance: &IR::SourceInstance,
    proof: &'a [u8],
) -> ia_core::VerificationResult<IR::TargetInstance>
where
    IR: InteractiveReduction,
    IR::SourceInstance: Encoding,
    [u8; SALT_LEN]: spongefish::NargDeserialize,
{
    verify_reduction_with_sponge_and_salt::<IR, Keccak, SALT_LEN>(
        ir,
        Keccak::default(),
        session,
        instance,
        proof,
    )
}

/// Non-interactive verifier for an IOR with default `SALT_LEN = 0`.
pub fn verify_reduction<'a, IR>(
    ir: &IR,
    session: [u8; 64],
    instance: &IR::SourceInstance,
    proof: &'a [u8],
) -> ia_core::VerificationResult<IR::TargetInstance>
where
    IR: InteractiveReduction,
    IR::SourceInstance: Encoding,
{
    verify_reduction_with_salt::<IR, 0>(ir, session, instance, proof)
}
