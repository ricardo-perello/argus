# Advanced Patterns

The advanced examples combine native roles, preprocessing, reductions,
composition, and backend-owned transcript binding.

## Asymmetric Preprocessing

`preprocessed_lookup` uses three types:

```text
LookupIndexer
LookupProver
LookupVerifier
```

The indexer derives:

```text
ProverKey   = table plus Merkle tree
VerifierKey = Merkle root plus table length
```

The prover sends the opened leaf and authentication path. The verifier checks the
opening against its compact key. The table binding happens through
`CommittedIndex`, not through protocol-local transcript calls.

```bash
cargo run -p argus-examples --bin preprocessed_lookup
```

## WARP

WARP exposes independent role families:

```text
WarpReductionIndexer / Prover / Verifier
WarpDeciderIndexer   / Prover / Verifier
FullWarpIndexer      / Prover / Verifier
```

`FullWarp` remains manually single-indexed so its committed-index encoding and
proof transcript stay unchanged. See [WARP](../protocols/warp.md).

## No Role Views or Recombination

Production code does not wrap a complete body and hide one method. It authors
the desired capability on a concrete type:

```rust,ignore
let prover = dsfs::argument_prover(
    native_prover_body,
    dsfs::Keccak::default(),
);
let verifier = dsfs::argument_verifier(
    native_verifier_body,
    dsfs::Keccak::default(),
);
```

There are no `into_prover` / `into_verifier` views, full conjunction traits,
`CombinedIA`, or `CombinedNarg`. If an application needs both roles, it keeps
the two values side by side. This preserves an actual dependency boundary:
verifier-only code does not contain the prover implementation.

## Compiled Roles as Interactive Roles

When a compiled NARG must be embedded as a one-message interactive argument, use
the matching adapter:

- `NargProverAsInteractiveArgument`
- `NargVerifierAsInteractiveArgument`

These adapters remain role-specific and do not reconstruct a combined object.

## External Compatibility

Compatibility work belongs in the bridge crate, DSFS transcript initialization,
protocol-id wiring, and golden-vector tests. `sigma-bridge` is the main example.
Sponge operations should not leak into ordinary protocol implementations.
