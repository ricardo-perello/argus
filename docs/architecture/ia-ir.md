# IA, IR, and Composition

Argus has two protocol shapes.

An `InteractiveArgument` proves a relation and the verifier returns
accept/reject:

```rust
pub trait InteractiveArgument {
    type Instance;
    type Witness;

    fn protocol_id(&self) -> impl AsRef<[u8]>;
    fn prove<P: ProverChannel>(&self, ch: &mut P, instance: &Self::Instance, witness: &Self::Witness);
    fn verify<V: VerifierChannel>(&self, ch: &mut V, instance: &Self::Instance) -> VerificationResult<()>;
}
```

An `InteractiveReduction` transforms a source relation into a target relation:

```rust
pub trait InteractiveReduction {
    type SourceInstance;
    type TargetInstance;
    type SourceWitness;
    type TargetWitness;

    fn protocol_id(&self) -> impl AsRef<[u8]>;
    fn prove<P: ProverChannel>(&self, ch: &mut P, instance: &Self::SourceInstance, witness: &Self::SourceWitness)
        -> (Self::TargetInstance, Self::TargetWitness);
    fn verify<V: VerifierChannel>(&self, ch: &mut V, instance: &Self::SourceInstance)
        -> VerificationResult<Self::TargetInstance>;
}
```

## Composition Types

`ChainedReduction<First, Second>` composes two reductions:

```text
IR1: R0 -> R1
IR2: R1 -> R2
IR2 after IR1: R0 -> R2
```

`ReducedArgument<Reduction, Argument>` composes a reduction with a final
argument:

```text
IR: R0 -> R1
IA: proves R1
IR followed by IA: proves R0
```

Composition also composes protocol IDs using an injective length-prefixed
encoding, so nested protocols remain domain-separated.

## Security Composition

For security metadata, composition threads instance bounds through the
intermediate relation. This matters because the intermediate target instance is
verifier-produced and transcript-dependent.

`ChainedReduction` evaluates:

1. the first reduction profile on the source params or source bound,
2. the first reduction's target bound,
3. the second reduction profile on that target bound.

`ReducedArgument` evaluates:

1. the reduction profile on the source params or source bound,
2. the reduction's target bound,
3. the final argument profile on that target bound.

See [RBR and SR Soundness](../security/rbr-and-sr.md) and
[Instance-Aware Security](../security/instance-aware-security.md).
