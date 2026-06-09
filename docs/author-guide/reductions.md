# Reductions and Composition

An argument ends in accept or reject. A reduction ends in a new public instance.

```text
source instance + source witness
        |
        v
interactive reduction
        |
        v
target instance + target witness
```

The verifier computes only the target instance. The prover computes the target
instance and target witness.

## Native Reduction Roles

The shared macro routes witness types and `prove` only to the prover:

```rust,ignore
ia_core::impl_interactive_reduction! {
    impl {
        prover: MyReductionProver,
        verifier: MyReductionVerifier,
    }
    {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            ia_core::pad_protocol_id(b"my-reduction")
        }

        type SourceInstance = Source;
        type TargetInstance = Target;
        type SourceWitness = SourceWitness;
        type TargetWitness = TargetWitness;

        fn prove<C: ProverChannel<Unit = u8>>(
            &self,
            channel: &mut C,
            instance: &Self::SourceInstance,
            witness: &Self::SourceWitness,
        ) -> (Self::TargetInstance, Self::TargetWitness) {
            /* channel-only reduction logic */
        }

        fn verify<C: VerifierChannel<Unit = u8>>(
            &self,
            channel: &mut C,
            instance: &Self::SourceInstance,
        ) -> VerificationResult<Self::TargetInstance> {
            /* compute the target instance */
        }
    }
}
```

The generated verifier implementation has only the source and target instance
types. Role-specific suffix macros are available when bounds differ.

## Compose Per Role

`ChainedReduction<First, Second>` composes two reductions:

```text
First:  R0 -> R1
Second: R1 -> R2
Chain:  R0 -> R2
```

Build separate composition trees:

```rust,ignore
type PipelineProver =
    ChainedReduction<FirstReductionProver, SecondReductionProver>;
type PipelineVerifier =
    ChainedReduction<FirstReductionVerifier, SecondReductionVerifier>;
```

Prover composition requires matching intermediate instance and witness types.
Verifier composition requires only matching intermediate instance types.

`ReducedArgument<Reduction, Argument>` runs a reduction and then a final
argument:

```rust,ignore
type FullProver =
    ReducedArgument<PipelineProver, FinalArgumentProver>;
type FullVerifier =
    ReducedArgument<PipelineVerifier, FinalArgumentVerifier>;
```

## Preprocessing Composition

Instantiate a third composition tree for indexers:

```rust,ignore
type PipelineIndexer =
    ChainedReduction<FirstIndexer, SecondIndexer>;
```

Its structural setup is:

```text
Index       = (First::Index, Second::Index)
ProverKey   = (First::ProverKey, Second::ProverKey)
VerifierKey = (First::VerifierKey, Second::VerifierKey)
```

To embed a plain role in preprocessing composition, use the role-specific
adapters:

- `TrivialIndexer`
- `TrivialIndexedArgumentProver` / `TrivialIndexedArgumentVerifier`
- `TrivialIndexedReductionProver` / `TrivialIndexedReductionVerifier`

The `composition` example contains complete prover and verifier trees:

```bash
cargo run -p argus-examples --bin composition
```
