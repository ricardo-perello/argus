# Reductions

An argument ends in accept or reject. A reduction ends in a new instance.

Use a reduction when a protocol step transforms one claim into another claim:

```text
source relation R0
source instance x
source witness  w

interactive reduction

target relation R1
target instance y
target witness  v
```

The verifier computes `y`; the prover computes both `y` and `v`.

## Reduction Trait Shape

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
            /* send messages, read challenges, compute target + target witness */
        }

        fn verify<V: VerifierChannel<Unit = u8>>(
            &self,
            ch: &mut V,
            instance: &Source,
        ) -> VerificationResult<Target> {
            /* read messages, send challenges, compute target */
        }
    }
}
```

The verifier output is the target instance, not `()`.

## Example: Folding

The `composition` example has a toy reduction `FoldPairs`:

```text
(c0, c1, c2, c3, ...)
        |
        | random r
        v
(c0 + r c1, c2 + r c3, ...)
```

The prover sends witness values, receives the random challenge, and folds its
witness in the same way. The verifier reads the committed values, sends the
challenge, and folds the public claims.

The source relation and target relation have the same shape, but fewer claims.
Other reductions can change relation shape completely.

## Compile a Reduction with DSFS

```rust
use ia_core::NonInteractiveReduction;

let nir = spongefish_dsfs::plain_non_interactive_reduction(
    FoldPairs,
    spongefish_dsfs::Keccak::default(),
);

let (proof, target_instance, target_witness) =
    nir.prove(&session, &source_instance, &source_witness);

let verified_target =
    nir.verify(&session, &source_instance, &proof)?;
```

## Compose Reductions

`ChainedReduction<First, Second>` composes two reductions:

```text
First:  R0 -> R1
Second: R1 -> R2
Chain:  R0 -> R2
```

`ReducedArgument<Reduction, Argument>` runs a reduction and then proves the
target instance with an argument:

```text
Reduction: R0 -> R1
Argument:  proves R1
Combined:  proves R0
```

In the example:

```rust
type TwoFolds = ChainedReduction<FoldPairs, FoldPairs>;
type FoldAndAccumulate = ChainedReduction<TwoFolds, Accumulate>;
type FullProtocol = ReducedArgument<FoldAndAccumulate, EqualityCheck>;
```

Under the hood, composition is exactly the mathematical pipeline. The composed
prover runs the first protocol, then feeds its output into the second:

```rust
fn prove<P: ProverChannel<Unit = u8>>(
    &self,
    ch: &mut P,
    x0: &R0::SourceInstance,
    w0: &R0::SourceWitness,
) -> (R1::TargetInstance, R1::TargetWitness) {
    let (x1, w1) = self.first.prove(ch, x0, w0);
    self.second.prove(ch, &x1, &w1)
}
```

The composed verifier does the same thing, but it only carries instances:

```rust
fn verify<V: VerifierChannel<Unit = u8>>(
    &self,
    ch: &mut V,
    x0: &R0::SourceInstance,
) -> VerificationResult<R1::TargetInstance> {
    let x1 = self.first.verify(ch, x0)?;
    self.second.verify(ch, &x1)
}
```

For `ReducedArgument`, the final step is an argument instead of another
reduction:

```rust
fn prove<P: ProverChannel<Unit = u8>>(&self, ch: &mut P, x0: &X0, w0: &W0) {
    let (x1, w1) = self.reduction.prove(ch, x0, w0);
    self.argument.prove(ch, &x1, &w1);
}

fn verify<V: VerifierChannel<Unit = u8>>(
    &self,
    ch: &mut V,
    x0: &X0,
) -> VerificationResult<()> {
    let x1 = self.reduction.verify(ch, x0)?;
    self.argument.verify(ch, &x1)
}
```

The full protocol is an argument even though most of its work is reductions.

## Theory Note

Reductions are how Argus represents accumulation and folding systems. The
verifier does not merely check that a transcript is valid; it computes the next
claim. This lets the type system distinguish "I am done" from "I produced the
next instance that some later protocol must decide."
