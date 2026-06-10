# Channels

The channel API is the whole protocol boundary.

The prover side can:

```rust,ignore
ch.send_prover_message(&message);
let challenge = ch.read_verifier_message();
```

The verifier side can:

```rust,ignore
let message = ch.read_prover_message()?;
let challenge = ch.send_verifier_message();
```

## Meaning

On the prover side, `send_prover_message` means "commit this message to the
conversation." In DSFS, the backend appends it to the proof and absorbs it into
the sponge. In live mode, the backend sends it across a channel.

On the verifier side, `read_prover_message` means "receive the next prover
message and bind it before the next public coin." In DSFS verification, the
message is read from proof bytes and absorbed in the same position as during
proving.

Verifier messages are public coins:

- `read_verifier_message` gives the prover the next coin.
- `send_verifier_message` gives the verifier the next coin.

In live mode the verifier samples the coin. In DSFS the backend derives it from
the transcript.

## Message Type and Channel Unit

The channel traits have two levels of typing:

```rust,ignore
pub trait ProverChannel {
    type Unit;

    fn send_prover_message<PM>(&mut self, msg: &PM)
    where
        PM: Encoding<[Self::Unit]> + NargSerialize;

    fn read_verifier_message<VM>(&mut self) -> VM
    where
        VM: Decoding<[Self::Unit]>;
}
```

`PM` and `VM` are the Rust message types for a particular call: a group
element, field element, vector, Merkle path, or protocol-specific structure.

`Unit` is the alphabet used by the whole channel. The current DSFS path is
byte-oriented, so examples usually write:

```rust,ignore
fn prove<P: ProverChannel<Unit = u8>>(...)
fn verify<V: VerifierChannel<Unit = u8>>(...)
```

The codec vocabulary is still a design boundary to keep an eye on. Today
`ia-core` re-exports the codec traits needed by the DSFS path; a future backend
with a non-byte alphabet may motivate a smaller codec abstraction owned by
`ia-core`.

## Public-Coin Branching

The verifier may inspect a prover message before choosing the next public coin
type:

```rust,ignore
let commitment: Commitment = ch.read_prover_message()?;

if commitment.uses_small_domain() {
    let c: SmallChallenge = ch.send_verifier_message();
    /* continue */
} else {
    let c: LargeChallenge = ch.send_verifier_message();
    /* continue */
}
```

This remains public-coin if the branch is a deterministic public function of
the instance and transcript so far. It is not compatible with Argus/DSFS if the
challenge distribution depends on hidden verifier state or on manual transcript
operations in protocol code.

## What Not To Do

Protocol code must not:

- instantiate a sponge,
- call transcript methods directly,
- hash or absorb public input for Fiat-Shamir,
- derive challenges outside `send_verifier_message`,
- depend on the concrete proof byte layout.

If a protocol needs one of those operations, the operation belongs in a backend.
