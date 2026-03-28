//! Sequential composition of reductions and reduced arguments.

use crate::argument::{InteractiveArgument, Prove, Verify};
use crate::channel::{ProverChannel, VerifierChannel};
use crate::error::VerificationResult;
use crate::reduction::{InteractiveReduction, ReduceProve, ReduceVerify};
use crate::security::SecurityProfile;

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

    fn security() -> SecurityProfile {
        First::security().compose(&Second::security())
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

    fn security() -> SecurityProfile {
        R::security().compose(&A::security())
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
