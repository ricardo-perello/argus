# Channel Model

An Argus protocol is a channel program.

The prover side can send prover messages and receive public verifier messages:

```rust
ch.send_prover_message(&message);
let challenge = ch.read_verifier_message();
```

The verifier side can receive prover messages and produce public verifier
messages:

```rust
let message = ch.read_prover_message()?;
let challenge = ch.send_verifier_message();
```

Those four calls are the protocol boundary. They describe the public-coin
conversation without saying how it is transported or how public coins are
derived.

## Backend Meaning

In `spongefish-dsfs`, a prover message is both proof data and transcript input:
it is appended to the NARG and absorbed before the next challenge. A verifier
message is squeezed from the sponge. During verification, the same prover
messages are read from proof bytes, absorbed in the same order, and used to
replay the same challenges.

In `live-channel`, the verifier samples public coins and sends them to the
prover through an in-process channel. There is no proof artifact.

The protocol body does not change between these executions.

## Public-Coin Branching

The verifier may inspect a prover message before deciding which public coin type
comes next:

```rust
let commitment: Commitment = ch.read_prover_message()?;

if commitment.uses_small_domain() {
    let c: SmallChallenge = ch.send_verifier_message();
    /* continue */
} else {
    let c: LargeChallenge = ch.send_verifier_message();
    /* continue */
}
```

This is still a public-coin protocol when the branch and challenge distribution
are deterministic public functions of the instance and transcript so far. It
does not fit the Argus/DSFS model if the challenge distribution depends on
hidden verifier state or on manual transcript operations performed by protocol
code.

## Rule

Protocol implementations should read like the mathematical protocol:

- send all prover messages for the round,
- read or send the public challenge,
- continue,
- return accept/reject for an argument or a target instance for a reduction.

Transcript ordering is a backend obligation. If protocol code needs direct
access to transcript state, the abstraction boundary is leaking.
