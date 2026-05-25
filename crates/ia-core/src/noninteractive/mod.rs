//! Non-interactive argument and reduction abstractions.
//!
//! The IA traits model public-coin protocols as channel programs. The traits in
//! this module model the result after a compiler such as DSFS has removed the
//! verifier's live randomness and produced a single non-interactive artifact.
//!
//! `ia-core` owns these types because they are abstract protocol vocabulary:
//! they say what a non-interactive argument or reduction is, but they do not
//! specify Fiat-Shamir, duplex sponges, domain separation, or any concrete proof
//! layout. Concrete compilers live outside this crate and implement these traits.

mod adapter;
mod proof;

pub use adapter::NargAsInteractiveArgument;
pub use proof::NargProof;

use crate::{Preprocessed, VerificationResult};

/// Abstract non-interactive argument.
///
/// A `NonInteractiveArgument` verifies membership of an `Instance` using a
/// [`NargProof`], with optional session data bound into the compiled transcript.
/// Unlike [`crate::InteractiveArgument`], there is no channel: the prover
/// returns a proof artifact and the verifier checks that artifact.
pub trait NonInteractiveArgument {
    /// Public session or context data bound into the non-interactive proof.
    type Session;
    /// Public statement being proved.
    type Instance;
    /// Private witness used by the prover.
    type Witness;

    /// Protocol identifier for the non-interactive argument.
    ///
    /// For compilers, this should identify the compiled proof system, not only
    /// the underlying interactive protocol. If the proof layout, sponge choice,
    /// salt policy, or transcript derivation changes, the compiler-level domain
    /// separation must change as well.
    fn protocol_id(&self) -> impl AsRef<[u8]>;

    /// Produce a non-interactive proof for `instance` using `witness`.
    fn prove(
        &self,
        session: &Self::Session,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> NargProof;

    /// Verify a non-interactive proof for `instance`.
    fn verify(
        &self,
        session: &Self::Session,
        instance: &Self::Instance,
        proof: &NargProof,
    ) -> VerificationResult<()>;
}

/// Abstract non-interactive reduction.
///
/// A non-interactive reduction proves that a source instance reduces to a target
/// instance. Verification returns the target instance instead of a boolean
/// accept/reject result, mirroring [`crate::InteractiveReduction`].
///
/// Proving returns the proof plus the target instance/witness pair so callers can
/// continue a reduction pipeline without replaying the verifier.
pub trait NonInteractiveReduction {
    /// Public session or context data bound into the non-interactive proof.
    type Session;
    /// Public source statement before reduction.
    type SourceInstance;
    /// Public target statement produced by the reduction.
    type TargetInstance;
    /// Private witness for the source statement.
    type SourceWitness;
    /// Private witness for the target statement produced by the prover.
    type TargetWitness;

    /// Protocol identifier for the non-interactive reduction.
    fn protocol_id(&self) -> impl AsRef<[u8]>;

    /// Produce a reduction proof and the reduced target statement/witness pair.
    fn prove(
        &self,
        session: &Self::Session,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (NargProof, Self::TargetInstance, Self::TargetWitness);

    /// Verify a reduction proof and return the reduced target statement.
    fn verify(
        &self,
        session: &Self::Session,
        instance: &Self::SourceInstance,
        proof: &NargProof,
    ) -> VerificationResult<Self::TargetInstance>;
}

/// Non-interactive argument produced from a preprocessed (indexed) body.
///
/// A marker trait combining [`NonInteractiveArgument`] with the
/// [`Preprocessed`] capability. The actual
/// accessors (`prover_key`, `verifier_key`, `committed_index`) live on
/// `Preprocessed`, which is the single discoverable home for preprocessing
/// keys regardless of which lattice plane (IA/IR or NARG) the wrapper sits on.
///
/// Plain NARGs (e.g. `DsfsArgument<plain_ia>`) do NOT implement `Preprocessed` and
/// therefore do NOT satisfy this bound: the type system enforces that a
/// generic consumer with bound `T: PreprocessingNonInteractiveArgument` provably
/// receives a NARG built from a preprocessed body.
pub trait PreprocessingNonInteractiveArgument: NonInteractiveArgument + Preprocessed {}

impl<T> PreprocessingNonInteractiveArgument for T where T: NonInteractiveArgument + Preprocessed {}

/// Non-interactive reduction produced from a preprocessed (indexed) body.
///
/// Reduction counterpart to [`PreprocessingNonInteractiveArgument`]; same composition,
/// same strong-typing argument.
pub trait PreprocessingNonInteractiveReduction: NonInteractiveReduction + Preprocessed {}

impl<T> PreprocessingNonInteractiveReduction for T where T: NonInteractiveReduction + Preprocessed {}
