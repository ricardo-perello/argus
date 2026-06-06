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

## Prover / Verifier Roles

Each leaf execution trait is split into a prover half and a verifier half (for
example `InteractiveArgumentProver` / `InteractiveArgumentVerifier`), with the
familiar full trait as their conjunction. Authoring is unchanged — the macro
emits both halves from one block — but you can now compile and hold *one* role:

```rust
use ia_core::prelude::*;

// Ergonomic role views over a full body:
let prover   = dsfs::plain_non_interactive_argument(body.into_prover(),   dsfs::Keccak::default());
let verifier = dsfs::plain_non_interactive_argument(body.into_verifier(), dsfs::Keccak::default());
```

`into_prover()` / `into_verifier()` (the `ProverOnly<T>` / `VerifierOnly<T>`
wrappers) expose only one executable half — an API boundary; the wrapped body
still contains both algorithms. A *genuinely* one-sided body — a type that
implements only `…Verifier` — goes further: the other algorithm does not exist
for it at all (the recursion-relevant case).

For preprocessing protocols, keys are passed explicitly on each call; there is no
stateful key-binding wrapper:

```rust
let proof = prover.prove(&pk, &session, &instance, &witness);
verifier.verify(&vk, &session, &instance, &proof)?;
```

The capability boundary is key possession: proving needs the prover key,
verification needs the verifier key. Two independently-built halves can be
recombined — `CombinedIA` at the body level, `spongefish_dsfs::CombinedNarg` at
the compiled-NARG level.

See [Prover/Verifier Split](../prover-verifier-split-presentation.md) for the full
picture.

## External Compatibility

Some code exists to match external proof layouts. In this workspace,
`sigma-bridge` does that for selected `sigma-proofs` paths.

Compatibility work usually belongs in:

- the bridge crate,
- DSFS transcript initialization,
- protocol-id wiring,
- golden vector tests.

It should not leak sponge operations into ordinary protocol implementations.
