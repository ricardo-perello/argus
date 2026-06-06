# Author Guide

Protocol authors should start from the interactive protocol, not from the proof
bytes.

In Argus, the author writes a public-coin conversation against abstract
channels. The backend decides whether that conversation is run live or compiled
with DSFS.

```text
author protocol
  prove(channel, instance, witness)
  verify(channel, instance)
        |
        v
ia-core channel traits
        |
        +-- spongefish-dsfs: transcript + proof bytes
        |
        +-- live-channel: interactive messages
```

The protocol body should not know whether a challenge came from a live verifier
or from a sponge. It should only express the next public coin in the
conversation.

## Pick the Shape

Most authors implement one of four interactive shapes:

- `InteractiveArgument`: plain accept/reject protocol.
- `InteractiveReduction`: plain protocol that outputs a target instance.
- `PreprocessingInteractiveArgument`: keyed accept/reject protocol.
- `PreprocessingInteractiveReduction`: keyed reduction.

The non-interactive traits are usually backend results. For example,
`spongefish-dsfs` turns an `InteractiveArgument` into a
`NonInteractiveArgument`.

Each of these traits is the conjunction of a `…Prover` half (`prove`) and a
`…Verifier` half (`verify`). You author one block with both methods exactly as
before — the macro emits the halves — so the split is invisible while writing a
protocol. It only matters when *running*: `.prove()` / `.verify()` live on the
halves, so bring them into scope with `use ia_core::prelude::*;`, and you can
compile/hold just one role (`body.into_prover()`). See
[Prover/Verifier Split](../prover-verifier-split-presentation.md).

## Keep the Boundary Clean

Inside protocol code, use only:

```rust
ch.send_prover_message(&msg);
let challenge = ch.read_verifier_message();

let msg = ch.read_prover_message()?;
let challenge = ch.send_verifier_message();
```

Do not instantiate a sponge, absorb public input, squeeze a challenge, parse
transcript bytes, or perform Fiat-Shamir logic in the protocol body. Those jobs
belong to the backend.

That rule is what lets the same protocol run through DSFS, run live, compose
with reductions, and remain a possible target for future compiler work.

Start with [Protocol Types](protocol-types.md), then implement the Schnorr-style
example in [First Argument](first-argument.md).
