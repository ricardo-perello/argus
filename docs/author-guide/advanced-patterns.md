# Advanced Patterns

Once the basic authoring path is clear, the rest of Argus is mostly composition
of the same ideas.

## Merkle Lookup

`preprocessed_lookup` demonstrates asymmetric preprocessing:

```text
Index       = public lookup table
ProverKey   = table + Merkle tree
VerifierKey = Merkle root + table length
Instance    = (row, claimed value)
Witness     = ()
```

The prover sends:

- the opened leaf value,
- one sibling hash per Merkle level.

The verifier:

- reads the leaf and siblings from the channel,
- reconstructs the root,
- checks the root against `vk.root`,
- checks the leaf equals the claimed value.

The transcript binding to the table happens through `CommittedIndex`, not by
having the protocol body absorb the root manually.

Run it with:

```bash
cargo run -p argus-examples --bin preprocessed_lookup
```

## WARP

WARP is expressed as preprocessing reductions plus a final argument. That is
exactly the place where Argus's distinction between reductions and arguments is
useful:

```text
preprocessing reduction(s): transform the claim
final argument: decide the final claim
```

The DSFS path compiles the composed channel program, while preprocessing keys
remain explicit inputs. See `crates/warp` and
`docs/protocols/warp.md` for the current shape.

The exported WARP types make the composition first-class:

```text
WarpReduction : preprocessing reduction
  source instance/witness  -> accumulated instance/witness

WarpDecider : preprocessing argument
  accumulated instance/witness -> accept/reject

FullWarp : preprocessing argument
  prove:  WarpReduction::prove, then WarpDecider::prove
  verify: WarpReduction::verify, then WarpDecider::verify
```

In code, `FullWarp` is not magic. Its prover does the same thing the author
would write by hand:

```rust
let (target_instance, target_witness) =
    self.reduction.prove(ch, pk, instance, witness);

self.decider
    .prove(ch, &(), &target_instance, &target_witness);
```

The verifier mirrors it:

```rust
let target_instance = self.reduction.verify(ch, vk, instance)?;
self.decider.verify(ch, vk, &target_instance)
```

## Trivial Indexed Adapters

There is no blanket conversion from every plain protocol into a preprocessing
protocol. Mixed composition must be explicit.

Use:

- `TrivialIndexedArgument`
- `TrivialIndexedReduction`

These wrappers give a plain protocol an empty index and empty committed index.
They are useful when composing with preprocessing protocols, but they make the
choice visible at the call site.

## Security Metadata

Security metadata is intentionally separate from executable protocol code.

Arguments implement `ArgumentSecurity`; reductions implement
`ReductionSecurity`. Preprocessing protocols use the preprocessing variants,
which separate index-derived data from per-instance data.

This matters because many reductions have bounds that depend on instance size,
degree, number of rounds, or indexed relation parameters. The executable
protocol should not hide that analysis inside transcript code.

## External Compatibility

Some protocols need to match an external proof layout or ciphersuite. In this
workspace, `sigma-bridge` does that for `sigma-proofs`.

Compatibility work usually belongs in:

- the bridge crate,
- DSFS transcript initialization,
- protocol ID wiring,
- test vectors.

It should not leak sponge operations into ordinary protocol implementations.

## Where To Look Next

- `crates/argus-examples/src/bin/schnorr.rs` for the smallest plain argument.
- `crates/argus-examples/src/bin/composition.rs` for reductions.
- `crates/argus-examples/src/bin/preprocessed_schnorr.rs` for the smallest
  preprocessing argument.
- `crates/argus-examples/src/bin/preprocessed_lookup.rs` for asymmetric keys and
  Merkle openings.
- `crates/warp` for a larger composed preprocessing protocol.
