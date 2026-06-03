# Compile with DSFS

DSFS turns the interactive channel program into a non-interactive proof.

For a plain argument:

```rust
use ia_core::NonInteractiveArgument;
use spongefish_dsfs as dsfs;

let session = spongefish::session!("schnorr example");
let schnorr = Schnorr::<G>::default();

let nia = dsfs::plain_non_interactive_argument(
    schnorr,
    dsfs::Keccak::default(),
);

let proof = nia.prove(&session, &instance, &witness);
nia.verify(&session, &instance, &proof)?;
```

The constructor consumes the interactive body and a transcript sponge
configuration. The returned value implements `NonInteractiveArgument`.

## What DSFS Does

During proving, DSFS:

- derives the transcript domain separator,
- absorbs protocol/session/public input before the first challenge,
- records prover messages into the proof string,
- absorbs prover messages before squeezing challenges,
- returns a `NargProof`.

During verification, DSFS:

- rebuilds the same domain separator,
- reads prover messages from proof bytes,
- absorbs them in the same order,
- squeezes the same challenges,
- rejects if the protocol check fails or proof bytes are malformed/trailing.

The protocol body sees only the channel API.

## Session

The `Session` is public context bound into the proof. Use it for application
context such as statement grouping, batch identity, or higher-level protocol
state.

```rust
let session = spongefish::session!("my application session");
```

A proof for one session should not verify under another session.

## Plain Reductions

DSFS can also compile reductions:

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

The verifier returns the target instance because reductions produce claims, not
just accept/reject bits.

## Sponge Choice

Argus's standard DSFS path uses Keccak:

```rust
dsfs::Keccak::default()
```

`StdHash` is available for explicit compatibility with spongefish or
`sigma-proofs` layouts. Do not silently change sponge choice for an existing
protocol without reviewing the DSFS-level protocol ID and transcript fixtures.

## Backend Ownership

If you find yourself wanting to call a sponge method from protocol code, stop.
The DSFS backend is the only layer that should touch sponge operations.
