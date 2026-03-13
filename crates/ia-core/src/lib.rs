//! Core abstractions for public-coin interactive arguments and reductions.
//!
//! Defines channel traits, the `InteractiveArgument` interface, and the
//! `InteractiveReduction` interface.
//!
//! Codec traits (`Encoding`, `Decoding`) are re-exported from spongefish.
//! `Deserialize` is defined here with a blanket impl from
//! `spongefish::NargDeserialize`.
#![no_std]

/// Verification failed.
#[derive(Debug, Clone, Copy)]
pub struct VerificationError;

/// Result type for verification operations.
pub type VerificationResult<T> = Result<T, VerificationError>;

pub use spongefish::{Decoding, Encoding};

// ---------------------------------------------------------------------------
// Deserialize: ia-core's own deserialization trait
// ---------------------------------------------------------------------------

/// Reconstruct a typed value from a byte buffer.
///
/// This is the inverse of [`Encoding`]: given the serialized bytes of a
/// prover message, produce the original value.  Blanket-implemented for
/// every type that has [`spongefish::NargDeserialize`].
pub trait Deserialize: spongefish::NargDeserialize {
    fn deserialize(buf: &mut &[u8]) -> VerificationResult<Self>;
}

impl<T: spongefish::NargDeserialize> Deserialize for T {
    fn deserialize(buf: &mut &[u8]) -> VerificationResult<Self> {
        T::deserialize_from_narg(buf).map_err(|_| VerificationError)
    }
}

// ---------------------------------------------------------------------------
// Channel traits -- method-level generics, generic over unit type U
// ---------------------------------------------------------------------------

/// Prover-side channel: send prover messages and read verifier challenges.
///
/// Generic over the sponge unit type `U` (default `u8` for byte-oriented
/// hash functions; a field element for algebraic sponges in recursive
/// settings).
pub trait ProverChannel<U = u8> {
    fn send_prover_message<PM: Encoding<[U]>>(&mut self, msg: &PM);
    fn read_verifier_message<VM: Decoding<[U]>>(&mut self) -> VM;
}

/// Verifier-side channel: read prover messages and derive verifier challenges.
pub trait VerifierChannel<U = u8> {
    fn read_prover_message<PM: Encoding<[U]> + Deserialize>(&mut self) -> VerificationResult<PM>;
    fn send_verifier_message<VM: Decoding<[U]>>(&mut self) -> VM;
}

// ---------------------------------------------------------------------------
// Interactive Argument traits
// ---------------------------------------------------------------------------

/// Metadata for a public-coin interactive argument.
pub trait InteractiveArgument {
    /// Public statement.
    type Instance;
    /// Prover's private input.
    type Witness;

    /// Unique 64-byte protocol identifier for domain separation.
    fn protocol_id() -> [u8; 64];
}

/// Prover logic: writes messages to and reads challenges from a `ProverChannel`.
pub trait Prove<P: ProverChannel>: InteractiveArgument {
    fn prove(ch: &mut P, instance: &Self::Instance, witness: &Self::Witness);
}

/// Verifier logic: reads messages from and derives challenges from a `VerifierChannel`.
pub trait Verify<V: VerifierChannel>: InteractiveArgument {
    fn verify(ch: &mut V, instance: &Self::Instance) -> VerificationResult<()>;
}

// ---------------------------------------------------------------------------
// Interactive Reduction traits
// ---------------------------------------------------------------------------

/// Metadata for a public-coin interactive oracle reduction.
///
/// Unlike an `InteractiveArgument` whose verifier outputs accept/reject,
/// an `InteractiveReduction` verifier outputs a **new instance** of a
/// (potentially simpler) target relation.  The prover consumes a
/// *source* witness and produces a *target* witness for the reduced claim.
pub trait InteractiveReduction {
    /// Input instance (the claim being reduced).
    type SourceInstance;
    /// Output instance (the reduced claim the verifier computes).
    type TargetInstance;
    /// Prover's private input for the source relation.
    type SourceWitness;
    /// Prover's output: private input for the target relation.
    type TargetWitness;

    /// Unique 64-byte protocol identifier for domain separation.
    fn protocol_id() -> [u8; 64];
}

/// Prover logic for an interactive reduction.
///
/// Takes `(source_instance, source_witness)` and returns both the target
/// instance and target witness.  In a public-coin protocol the prover can
/// always compute the target instance (it sees the same transcript as the
/// verifier).  Returning it here enables automatic sequential composition.
pub trait ReduceProve<P: ProverChannel>: InteractiveReduction {
    fn prove(
        ch: &mut P,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (Self::TargetInstance, Self::TargetWitness);
}

/// Verifier logic for an interactive reduction: returns a new instance,
/// not accept/reject.
pub trait ReduceVerify<V: VerifierChannel>: InteractiveReduction {
    fn verify(
        ch: &mut V,
        instance: &Self::SourceInstance,
    ) -> VerificationResult<Self::TargetInstance>;
}

// ---------------------------------------------------------------------------
// Sequential composition
// ---------------------------------------------------------------------------

/// Derives a 64-byte protocol identifier from two sub-protocol IDs and a
/// domain-separation tag.  Non-commutative: swapping `first` and `second`
/// produces a different result.
fn derive_composition_id(tag: u8, first: [u8; 64], second: [u8; 64]) -> [u8; 64] {
    let mut id = [0u8; 64];
    let mut i = 0;
    while i < 64 {
        id[i] = first[i] ^ second[(i + 1) % 64] ^ tag.wrapping_add(i as u8);
        i += 1;
    }
    id
}

/// Sequential composition of two interactive reductions: IR . IR -> IR.
///
/// `First` reduces `(SourceInstance, SourceWitness)` into an intermediate
/// relation; `Second` reduces that intermediate relation into the final
/// `(TargetInstance, TargetWitness)`.
///
/// Both prover and verifier are auto-composed:
///   - Prover: runs `First::prove` to get `(x2, w2)`, then `Second::prove(x2, w2)`.
///   - Verifier: runs `First::verify` to get `x2`, then `Second::verify(x2)`.
pub struct ChainedReduction<First, Second>(core::marker::PhantomData<(First, Second)>);

impl<First, Second> InteractiveReduction for ChainedReduction<First, Second>
where
    First: InteractiveReduction,
    Second: InteractiveReduction<
        SourceInstance = First::TargetInstance,
        SourceWitness = First::TargetWitness,
    >,
{
    type SourceInstance = First::SourceInstance;
    type TargetInstance = Second::TargetInstance;
    type SourceWitness = First::SourceWitness;
    type TargetWitness = Second::TargetWitness;

    fn protocol_id() -> [u8; 64] {
        derive_composition_id(0x01, First::protocol_id(), Second::protocol_id())
    }
}

impl<First, Second, P> ReduceProve<P> for ChainedReduction<First, Second>
where
    P: ProverChannel,
    First: ReduceProve<P>,
    Second: ReduceProve<P>
        + InteractiveReduction<
            SourceInstance = First::TargetInstance,
            SourceWitness = First::TargetWitness,
        >,
{
    fn prove(
        ch: &mut P,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (Self::TargetInstance, Self::TargetWitness) {
        let (x2, w2) = First::prove(ch, instance, witness);
        Second::prove(ch, &x2, &w2)
    }
}

impl<First, Second, V> ReduceVerify<V> for ChainedReduction<First, Second>
where
    V: VerifierChannel,
    First: ReduceVerify<V>,
    Second: ReduceVerify<V>
        + InteractiveReduction<
            SourceInstance = First::TargetInstance,
            SourceWitness = First::TargetWitness,
        >,
{
    fn verify(
        ch: &mut V,
        instance: &Self::SourceInstance,
    ) -> VerificationResult<Self::TargetInstance> {
        let intermediate = First::verify(ch, instance)?;
        Second::verify(ch, &intermediate)
    }
}

/// Sequential composition of an interactive reduction followed by an
/// interactive argument: IR . IA -> IA.
///
/// `Reduction` reduces the source relation into a target relation whose
/// instance and witness types match the `Argument`.  The composed protocol
/// is itself an interactive argument (the verifier outputs accept/reject).
///
/// Both prover and verifier are auto-composed:
///   - Prover: runs `Reduction::prove` to get `(x2, w2)`, then `Argument::prove(x2, w2)`.
///   - Verifier: runs `Reduction::verify` to get `x2`, then `Argument::verify(x2)`.
pub struct ReducedArgument<Reduction, Argument>(core::marker::PhantomData<(Reduction, Argument)>);

impl<R, A> InteractiveArgument for ReducedArgument<R, A>
where
    R: InteractiveReduction,
    A: InteractiveArgument<
        Instance = R::TargetInstance,
        Witness = R::TargetWitness,
    >,
{
    type Instance = R::SourceInstance;
    type Witness = R::SourceWitness;

    fn protocol_id() -> [u8; 64] {
        derive_composition_id(0x02, R::protocol_id(), A::protocol_id())
    }
}

impl<R, A, P> Prove<P> for ReducedArgument<R, A>
where
    P: ProverChannel,
    R: ReduceProve<P>,
    A: Prove<P>
        + InteractiveArgument<
            Instance = R::TargetInstance,
            Witness = R::TargetWitness,
        >,
{
    fn prove(ch: &mut P, instance: &Self::Instance, witness: &Self::Witness) {
        let (x2, w2) = R::prove(ch, instance, witness);
        A::prove(ch, &x2, &w2);
    }
}

impl<R, A, V> Verify<V> for ReducedArgument<R, A>
where
    V: VerifierChannel,
    R: ReduceVerify<V>,
    A: Verify<V>
        + InteractiveArgument<
            Instance = R::TargetInstance,
            Witness = R::TargetWitness,
        >,
{
    fn verify(ch: &mut V, instance: &Self::Instance) -> VerificationResult<()> {
        let target_instance = R::verify(ch, instance)?;
        A::verify(ch, &target_instance)
    }
}
