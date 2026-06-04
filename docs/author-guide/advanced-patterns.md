# Advanced Patterns

The advanced examples are mostly combinations of the same primitives:
preprocessing, reductions, composition, and backend-owned transcript binding.

## Asymmetric Preprocessing

`preprocessed_lookup` demonstrates asymmetric keys:

```text
Index       = public lookup table
ProverKey   = table + Merkle tree
VerifierKey = Merkle root + table length
Instance    = (row, claimed value)
Witness     = ()
```

The prover sends the opened leaf and Merkle siblings. The verifier reconstructs
the root and checks it against `vk.root`.

The table binding happens through `CommittedIndex`, not through manual
transcript calls in the protocol body.

```bash
cargo run -p argus-examples --bin preprocessed_lookup
```

## WARP

WARP is expressed as preprocessing reductions plus a final argument:

```text
WarpReduction : preprocessing reduction
  source instance/witness -> accumulated instance/witness

WarpDecider : preprocessing argument
  accumulated instance/witness -> accept/reject

FullWarp : preprocessing argument
  run the reduction, then run the decider
```

This is the place where Argus's distinction between reductions and arguments is
useful. The reduction produces a new claim; the decider proves that the final
claim is valid.

See [WARP](../protocols/warp.md) for the case study.

## Role Wrappers

For preprocessing non-interactive protocols, optional role wrappers can pair a
compiled protocol with one key:

```rust
let prover = Prover::new(&pnia, &pk);
let verifier = Verifier::new(&pnia, &vk);
```

These wrappers are ergonomic views, not a cryptographic boundary. The real
capability boundary is key possession: proving requires a prover key, and
verification requires a verifier key.

## External Compatibility

Some code exists to match external proof layouts. In this workspace,
`sigma-bridge` does that for selected `sigma-proofs` paths.

Compatibility work usually belongs in:

- the bridge crate,
- DSFS transcript initialization,
- protocol-id wiring,
- golden vector tests.

It should not leak sponge operations into ordinary protocol implementations.
