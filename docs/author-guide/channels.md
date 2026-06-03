# Channels

An Argus protocol is a channel program.

The prover side can:

```rust
ch.send_prover_message(&message);
let challenge = ch.read_verifier_message();
```

The verifier side can:

```rust
let message = ch.read_prover_message()?;
let challenge = ch.send_verifier_message();
```

Those four calls are the whole protocol boundary.

## Prover and Verifier Views

On the prover side, `send_prover_message` means "commit this message to the
conversation." In DSFS it is also appended to the proof string and absorbed into
the sponge. In a live backend it is sent across a channel.

On the verifier side, `read_prover_message` means "receive the next prover
message and bind it before deriving the next public coin." In DSFS verification
the message is read from proof bytes, then absorbed in the same place the prover
absorbed it.

For verifier challenges:

- `read_verifier_message` gives the prover the next public coin.
- `send_verifier_message` gives the verifier the next public coin.

In a live backend, the verifier samples the coin and sends it. In DSFS, the
backend squeezes it from the transcript. The protocol body does not change.

## Channel Alphabet

The real channel traits have two levels of typing:

```rust
pub trait ProverChannel {
    type Unit;

    fn send_prover_message<PM: Encoding<[Self::Unit]> + NargSerialize>(&mut self, msg: &PM);
    fn read_verifier_message<VM: Decoding<[Self::Unit]>>(&mut self) -> VM;
}
```

`PM` or `VM` is the Rust type of this particular message: a group element, a
field element, a vector, a Merkle sibling, and so on. It changes from one call
to the next.

`Unit` is the alphabet the whole channel speaks. For the current byte-oriented
DSFS path, `Unit = u8`, so every message type must know how to encode itself as
bytes. A future algebraic sponge backend might use field elements as the unit,
so its messages would implement `Encoding<[F]>` instead.

So both are needed:

```text
PM / VM = what object is being sent
Unit    = what alphabet that object is encoded into for this channel
```

Byte-oriented protocols usually write bounds like:

```rust
fn prove<P: ProverChannel<Unit = u8>>(...)
fn verify<V: VerifierChannel<Unit = u8>>(...)
```

The codec traits are currently re-exported from `spongefish` through `ia-core`.
That is a convenience for protocol authors, but it is also a real design seam:
`NargSerialize` is proof-artifact vocabulary, while the interactive channel
abstraction wants typed messages. See [Report Notes](../report-notes.md) for
the open question.

## Round Shape

A public-coin round should read like the math:

```text
prover sends all messages for the round
verifier sends a public challenge
prover continues
```

In code:

```rust
// Prover
ch.send_prover_message(&commitment);
let challenge = ch.read_verifier_message();
ch.send_prover_message(&response);

// Verifier
let commitment = ch.read_prover_message()?;
let challenge = ch.send_verifier_message();
let response = ch.read_prover_message()?;
```

The verifier does not manually absorb `commitment` before asking for
`challenge`; that is the backend's job. The verifier does read the message, and
it may inspect it before choosing what kind of public coin comes next.

That distinction matters. This is still compatible with public-coin protocols:

```rust
let commitment: Commitment = ch.read_prover_message()?;

if commitment.is_small_domain() {
    let c: SmallChallenge = ch.send_verifier_message();
    /* continue with the small-domain branch */
} else {
    let c: LargeChallenge = ch.send_verifier_message();
    /* continue with the large-domain branch */
}
```

The branch must be a deterministic public function of the instance and messages
the verifier has read. The challenge value itself is still public randomness
sampled by the verifier in live mode or squeezed by the backend in DSFS. What
would break the public-coin/DSFS story is a verifier challenge whose
distribution depends on hidden verifier state or on transcript operations the
protocol body performs manually.

## What Not To Do

Protocol code must not:

- Instantiate a sponge.
- Call spongefish transcript methods directly.
- Hash or absorb public input for Fiat-Shamir.
- Derive challenges outside `send_verifier_message`.
- Depend on the concrete proof byte layout.

If code needs any of those operations, it belongs in a backend.
