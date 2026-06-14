# Compile with DSFS

`spongefish-dsfs` compiles interactive roles into non-interactive roles while
owning all transcript mechanics.

## Plain Arguments

Compile the two roles independently:

```rust,ignore
use ia_core::prelude::*;
use spongefish_dsfs as dsfs;

let session = spongefish::session!("schnorr example");
let prover = dsfs::argument_prover(
    SchnorrProver::<G>::default(),
    dsfs::Keccak::default(),
);
let verifier = dsfs::argument_verifier(
    SchnorrVerifier::<G>::default(),
    dsfs::Keccak::default(),
);

let proof = prover.prove(&session, &instance, &witness);
verifier.verify(&session, &instance, &proof)?;
```

The prover wrapper implements `NonInteractiveArgumentProver`; the verifier
wrapper implements `NonInteractiveArgumentVerifier`. Neither wrapper contains
the opposite interactive role.

## What DSFS Owns

During proving, DSFS:

- derives the transcript domain separator,
- absorbs protocol, session, and public input before the first challenge,
- records prover messages into the proof,
- absorbs every prover message before squeezing the next challenge,
- returns a `NargProof`.

During verification, DSFS:

- rebuilds the same domain separator,
- reads prover messages from proof bytes,
- absorbs them in the same order,
- squeezes the same challenges,
- rejects malformed or trailing proof bytes.

Protocol code sees only the channel API.

## Session

The session is public context bound into the proof:

```rust,ignore
let session = spongefish::session!("my application session");
```

A proof for one session should not verify under another.

## Reductions

Reductions use role-specific constructors too:

```rust,ignore
let prover = dsfs::reduction_prover(
    reduction_prover,
    dsfs::Keccak::default(),
);
let verifier = dsfs::reduction_verifier(
    reduction_verifier,
    dsfs::Keccak::default(),
);

let (proof, target_instance, target_witness) =
    prover.prove(&session, &source_instance, &source_witness);

let verified_target =
    verifier.verify(&session, &source_instance, &proof)?;
```

## Preprocessing

DSFS does not implement or forward `Indexer`. Run indexing separately:

```rust,ignore
let (pk, vk) = indexer.preprocess(&index);

let prover = dsfs::preprocessing::argument_prover(
    argument_prover,
    dsfs::Keccak::default(),
);
let verifier = dsfs::preprocessing::argument_verifier(
    argument_verifier,
    dsfs::Keccak::default(),
);

let proof = prover.prove(&pk, &session, &instance, &witness);
verifier.verify(&vk, &session, &instance, &proof)?;
```

The compiled roles store no keys. Each derives committed-index bytes from the
key supplied to that role.

## Sponge Choice

Argus's standard DSFS path uses Keccak. `StdHash` is available only for explicit
compatibility with external layouts such as selected `sigma-proofs` vectors.
Changing sponge choice, salt policy, transcript initialization, or proof layout
requires a protocol-id review.
