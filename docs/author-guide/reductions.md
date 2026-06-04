# Reductions and Composition

An argument ends in accept or reject. A reduction ends in a new instance.

Use a reduction when a protocol step transforms one claim into another:

```text
source instance + source witness
        |
        v
interactive reduction
        |
        v
target instance + target witness
```

The verifier computes the target instance. The prover computes both the target
instance and target witness.

## Trait Shape

```rust
ia_core::impl_interactive_reduction! {
    impl InteractiveReduction for MyReduction {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            ia_core::pad_protocol_id(b"my-reduction")
        }

        type SourceInstance = Source;
        type TargetInstance = Target;
        type SourceWitness = SourceWitness;
        type TargetWitness = TargetWitness;

        fn prove<P: ProverChannel<Unit = u8>>(
            &self,
            ch: &mut P,
            instance: &Source,
            witness: &SourceWitness,
        ) -> (Target, TargetWitness) {
            /* channel-only reduction logic */
        }

        fn verify<V: VerifierChannel<Unit = u8>>(
            &self,
            ch: &mut V,
            instance: &Source,
        ) -> VerificationResult<Target> {
            /* compute the target instance */
        }
    }
}
```

## Compose Reductions

`ChainedReduction<First, Second>` composes two reductions when the target of the
first is the source of the second:

```text
First:  R0 -> R1
Second: R1 -> R2
Chain:  R0 -> R2
```

You can chain reductions as far as the types line up. The mathematical limit is
only that the composition is a finite sequential protocol; the practical Rust
limit is type size and readability. If a deeply nested type becomes unwieldy,
introduce named aliases or a protocol-specific wrapper.

`ReducedArgument<Reduction, Argument>` runs a reduction and then proves the
target instance with an argument:

```text
Reduction: R0 -> R1
Argument:  proves R1
Combined:  proves R0
```

The full protocol is an argument even though most of its work may be reductions.

## Preprocessing Composition

For preprocessing protocols, composition must combine more than execution. It
also combines indexes, prover keys, verifier keys, and committed-index bytes.

For two preprocessing components, the composed setup shape is structural:

```rust
type Index = (First::Index, Second::Index);
type ProverKey = (First::ProverKey, Second::ProverKey);
type VerifierKey = (First::VerifierKey, Second::VerifierKey);
```

During execution, each sub-key is routed to the corresponding component:

```rust
let (x1, w1) = self.first.prove(ch, &pk.0, x0, w0);
self.second.prove(ch, &pk.1, &x1, &w1)
```

The verifier mirrors this with `vk.0` and `vk.1`. The composed key commitment is
encoded as a tagged pair, so DSFS binds the combined indexed relation before the
first challenge.

Mixed plain/preprocessing composition uses `TrivialIndexedArgument` or
`TrivialIndexedReduction`. The empty index is explicit at the call site instead
of being introduced by a blanket conversion.

## Example

The `composition` example includes a toy `FoldPairs` reduction:

```text
(c0, c1, c2, c3, ...)
        |
        | random r
        v
(c0 + r c1, c2 + r c3, ...)
```

Run it with:

```bash
cargo run -p argus-examples --bin composition
```
