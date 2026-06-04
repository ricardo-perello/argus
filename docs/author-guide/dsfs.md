# Compile with DSFS

`spongefish-dsfs` turns an interactive channel program into a non-interactive
proof.

For a plain argument:

```rust
use ia_core::NonInteractiveArgument;
use spongefish_dsfs as dsfs;

let session = spongefish::session!("schnorr example");
let nia = dsfs::plain_non_interactive_argument(
    Schnorr::<G>::default(),
    dsfs::Keccak::default(),
);

let proof = nia.prove(&session, &instance, &witness);
nia.verify(&session, &instance, &proof)?;
```

The constructor consumes the interactive body and a sponge configuration. The
returned value implements `NonInteractiveArgument`.

## What DSFS Owns

During proving, DSFS:

- derives the transcript domain separator,
- absorbs protocol/session/public input before the first challenge,
- records prover messages into the proof,
- absorbs prover messages before squeezing challenges,
- returns a `NargProof`.

During verification, DSFS:

- rebuilds the same domain separator,
- reads prover messages from proof bytes,
- absorbs them in the same order,
- squeezes the same challenges,
- rejects malformed or trailing proof bytes.

The protocol body sees only the channel API.

## Session

The session is public context bound into the proof. Use it for application
context such as batch identity, statement grouping, or higher-level protocol
state.

```rust
let session = spongefish::session!("my application session");
```

A proof for one session should not verify under another.

## Reductions

Reductions compile the same way, but verification returns a target instance:

```rust
use ia_core::NonInteractiveReduction;

let nir = dsfs::plain_non_interactive_reduction(
    reduction,
    dsfs::Keccak::default(),
);

let (proof, target_instance, target_witness) =
    nir.prove(&session, &source_instance, &source_witness);

let verified_target =
    nir.verify(&session, &source_instance, &proof)?;
```

## Sponge Choice

Argus's standard DSFS path uses Keccak.

`StdHash` is available for explicit compatibility with external spongefish or
`sigma-proofs` layouts. Do not silently change sponge choice for an existing
proof format without reviewing protocol id, domain separation, and fixtures.
