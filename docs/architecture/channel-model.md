# Channel Model

An Argus protocol is a channel program. This is both an authoring model and a
compilation target: a protocol author can write an IA/IR directly, or another
compiler can output an IA/IR channel program.

The prover side writes prover messages and reads public verifier messages:

```rust
ch.send_prover_message(&message);
let challenge = ch.read_verifier_message();
```

The verifier side reads prover messages and sends public verifier messages:

```rust
let message = ch.read_prover_message()?;
ch.send_verifier_message(&challenge);
```

The same calls mean different things depending on the backend.

That bidirectionality is important for the long-term BCS direction. DSFS
consumes an IA and produces a NARG; an iBCS compiler would consume an IOP plus a
commitment scheme and produce an IA that uses the same channel interface.

## DSFS Backend

In `spongefish::dsfs`, prover messages are appended to the NARG string and
absorbed into the sponge. Verifier messages are squeezed from the sponge. During
verification, prover messages are read from proof bytes and absorbed in the same
order before the verifier squeezes the matching challenges.

This backend owns the transcript. Protocol code must not call sponge APIs or
derive Fiat-Shamir challenges directly.

## Live Backend

In `live-channel`, prover and verifier run as interactive parties. The verifier
samples public coins and sends them to the prover. This is useful for checking
that an IA/IR really is a public-coin protocol before compiling it with DSFS.

## Protocol Rule

Protocol implementations should be readable as the mathematical protocol:

- send all prover messages for the round,
- read or send the verifier challenge,
- continue to the next round,
- return accept/reject for an argument, or a target instance for a reduction.

Transcript ordering constraints are enforced by the backend boundary. See
[Transcript Invariants](../security/transcript-invariants.md).
