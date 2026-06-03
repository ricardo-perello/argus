# What Argus Provides

Argus is the interface layer for public-coin protocols.

A protocol author writes the conversation once, against abstract prover and
verifier channels. A backend then decides how that conversation is executed:

- `spongefish::dsfs` compiles it into a non-interactive proof by Fiat-Shamir.
- `live-channel` runs the same conversation interactively with verifier-sampled
  public coins.
- Future backends can reuse the same author-facing protocol code.

That separation is the main contribution. Protocol code describes the
mathematical protocol; backend code owns transcripts, replay, domain separation,
transport, sponge operations, and proof serialization.

```text
author protocol
  prove(ch, instance, witness)
  verify(ch, instance)
        |
        v
abstract channels
        |
        +--> DSFS backend: transcript + proof bytes
        |
        +--> live backend: interactive messages
```

Protocol code should not know whether a challenge was sampled by a live verifier
or squeezed from a sponge. It only says, "the verifier sends a challenge here."
The backend gives that sentence concrete meaning.

## What Authors Implement

Most authors implement one of four interactive protocol shapes:

- A plain interactive argument: the verifier accepts or rejects a statement.
- A plain interactive reduction: the verifier outputs a reduced statement.
- A preprocessing interactive argument: setup derives prover and verifier keys.
- A preprocessing interactive reduction: keyed setup plus reduction output.

The non-interactive traits are usually not implemented directly by protocol
authors. They are what a backend returns after compiling an interactive body.
For example, DSFS turns an `InteractiveArgument` into a
`NonInteractiveArgument`.

## The Rule of the Boundary

Inside protocol code, use only the channel methods:

```rust
ch.send_prover_message(&msg);
let challenge = ch.read_verifier_message();

let msg = ch.read_prover_message()?;
let challenge = ch.send_verifier_message();
```

Do not instantiate a sponge, absorb public input, squeeze a challenge, parse
transcript bytes, or perform Fiat-Shamir logic in the protocol body.

That rule keeps the security invariants centralized:

- Public inputs are bound before the first challenge.
- Prover messages are absorbed before the corresponding challenge.
- Verification replay is deterministic.
- The same protocol can be executed by multiple backends.

The next chapter gives the full type matrix before we build a concrete
argument.
