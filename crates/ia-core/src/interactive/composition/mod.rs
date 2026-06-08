//! Sequential composition of reductions and reduced arguments.

extern crate alloc;

use alloc::vec::Vec;

use crate::{ArgumentCore, ArgumentProverCore, ProtocolCore, ReductionCore, ReductionProverCore};

mod plain;
mod preprocessing;

/// Derives a variable-length protocol identifier from two sub-protocol IDs and a
/// domain-separation tag, using length-prefixed concatenation:
///   `tag || LE32(|first|) || first || LE32(|second|) || second`
/// This encoding is injective — no two distinct `(tag, first, second)` triples
/// produce the same byte string — so it's a safe input to the DSFS derivation.
pub(crate) fn derive_composition_id(tag: u8, first: &[u8], second: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + first.len() + 4 + second.len());
    out.push(tag);
    out.extend_from_slice(&(first.len() as u32).to_le_bytes());
    out.extend_from_slice(first);
    out.extend_from_slice(&(second.len() as u32).to_le_bytes());
    out.extend_from_slice(second);
    out
}

/// Sequential composition of two interactive reductions: IR . IR -> IR.
///
/// `First` reduces `(SourceInstance, SourceWitness)` into an intermediate
/// relation; `Second` reduces that intermediate relation into the final
/// `(TargetInstance, TargetWitness)`.
pub struct ChainedReduction<First, Second> {
    pub first: First,
    pub second: Second,
}

impl<First, Second> ChainedReduction<First, Second> {
    pub fn new(first: First, second: Second) -> Self {
        Self { first, second }
    }
}

impl<First, Second> ProtocolCore for ChainedReduction<First, Second>
where
    First: ProtocolCore,
    Second: ProtocolCore,
{
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        derive_composition_id(
            0x01,
            self.first.protocol_id().as_ref(),
            self.second.protocol_id().as_ref(),
        )
    }
}

impl<First, Second> ReductionCore for ChainedReduction<First, Second>
where
    First: ReductionCore,
    Second: ReductionCore<SourceInstance = First::TargetInstance>,
{
    type SourceInstance = First::SourceInstance;
    type TargetInstance = Second::TargetInstance;
}

impl<First, Second> ReductionProverCore for ChainedReduction<First, Second>
where
    First: ReductionProverCore,
    Second: ReductionProverCore<
            SourceInstance = First::TargetInstance,
            SourceWitness = First::TargetWitness,
        >,
{
    type SourceWitness = First::SourceWitness;
    type TargetWitness = Second::TargetWitness;
}

/// Default impl so `ChainedReduction<F, S>` can be zero-sized-constructed when
/// both subcomponents are `Default`.
impl<First: Default, Second: Default> Default for ChainedReduction<First, Second> {
    fn default() -> Self {
        Self {
            first: First::default(),
            second: Second::default(),
        }
    }
}

/// Sequential composition of an interactive reduction followed by an
/// interactive argument: IR . IA -> IA.
///
/// `Reduction` reduces the source relation into a target relation whose
/// instance and witness types match the `Argument`.  The composed protocol
/// is itself an interactive argument (the verifier outputs accept/reject).
pub struct ReducedArgument<Reduction, Argument> {
    pub reduction: Reduction,
    pub argument: Argument,
}

impl<R, A> ReducedArgument<R, A> {
    pub fn new(reduction: R, argument: A) -> Self {
        Self {
            reduction,
            argument,
        }
    }
}

impl<R, A> ProtocolCore for ReducedArgument<R, A>
where
    R: ProtocolCore,
    A: ProtocolCore,
{
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        derive_composition_id(
            0x02,
            self.reduction.protocol_id().as_ref(),
            self.argument.protocol_id().as_ref(),
        )
    }
}

impl<R, A> ArgumentCore for ReducedArgument<R, A>
where
    R: ReductionCore,
    A: ArgumentCore<Instance = R::TargetInstance>,
{
    type Instance = R::SourceInstance;
}

impl<R, A> ArgumentProverCore for ReducedArgument<R, A>
where
    R: ReductionProverCore,
    A: ArgumentProverCore<Instance = R::TargetInstance, Witness = R::TargetWitness>,
{
    type Witness = R::SourceWitness;
}

impl<R: Default, A: Default> Default for ReducedArgument<R, A> {
    fn default() -> Self {
        Self {
            reduction: R::default(),
            argument: A::default(),
        }
    }
}
