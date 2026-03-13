# live-channel: Interactive Protocol Execution

## Purpose

The `live-channel` crate provides `ProverChannel` and `VerifierChannel` implementations that enable truly interactive protocol execution. Prover and verifier run concurrently (e.g., in separate threads) and exchange messages through `std::sync::mpsc` channels.

This complements the `dsfs` crate, which compiles interactive arguments into non-interactive proofs via Fiat-Shamir. Both crates implement the same ia-core channel traits, so **identical protocol code** runs against either backend.

```
                    ia-core
                  ProverChannel
                  VerifierChannel
                   /          \
                  /            \
            dsfs                live-channel
     (non-interactive)         (interactive)
    sponge-backed F-S       mpsc-backed threads
    outputs proof bytes     real-time exchange
```

## API

### `channel_pair() -> (LiveProverChannel, LiveVerifierChannel)`

Creates a linked pair of channels. Internally sets up two mpsc channels: one for prover-to-verifier messages, one for verifier-to-prover challenges.

```rust
let (mut prover_ch, mut verifier_ch) = live_channel::channel_pair();

// Pass prover_ch to the prover thread, verifier_ch to the verifier thread.
```

### `LiveProverChannel`

Implements `ia_core::ProverChannel`.

- `send_prover_message<M: Encoding>` -- serializes the message via `Encoding::encode()` and sends the bytes to the verifier through mpsc.
- `read_verifier_message<C: Decoding>` -- receives raw challenge bytes from the verifier, constructs a `C::Repr` buffer, and calls `C::decode()` to produce the challenge value.

### `LiveVerifierChannel`

Implements `ia_core::VerifierChannel`.

- `read_prover_message<M: Encoding + NargDeserialize>` -- receives bytes from the prover and deserializes via `NargDeserialize::deserialize_from_narg()`.
- `send_verifier_message<C: Decoding>` -- samples fresh random bytes using `OsRng`, sends them to the prover, and decodes locally via `C::decode()`. Both sides call `decode` on identical bytes and get the identical challenge value.

## How challenges work

In DSFS, both prover and verifier independently squeeze the sponge to derive the same challenge deterministically. In a live channel, the verifier generates true randomness and transmits it:

1. Verifier creates `C::Repr::default()` (a buffer whose size is determined by the type).
2. Verifier fills the buffer with cryptographically secure random bytes (`OsRng`).
3. Verifier sends the raw bytes to the prover through mpsc.
4. Verifier calls `C::decode(repr)` to get the challenge locally.
5. Prover receives the same bytes, fills its own `Repr`, calls `C::decode(repr)`.

`Decoding::decode` is a pure function, so both sides produce the same value from the same bytes.

## How prover messages work

1. Prover calls `msg.encode()` (from `Encoding`) to get a byte representation.
2. Prover sends the bytes to the verifier through mpsc.
3. Verifier receives the bytes and calls `M::deserialize_from_narg()` to reconstruct the message.

`Encoding::encode` and `NargDeserialize::deserialize_from_narg` are inverse operations for the same type, ensuring the round-trip is lossless.

## Example: live Schnorr

[schnorr_live.rs](../crates/argus-examples/src/bin/schnorr_live.rs) runs the Schnorr protocol interactively:

```rust
let (mut prover_ch, mut verifier_ch) = live_channel::channel_pair();

let prover_handle = thread::spawn(move || {
    Schnorr::<G>::prove(&mut prover_ch, &instance, &sk);
});

let verifier_handle = thread::spawn(move || {
    Schnorr::<G>::verify(&mut verifier_ch, &instance)
});
```

The `Schnorr` type, its `Prove` impl, and its `Verify` impl are identical to those in the DSFS example (`schnorr.rs`). The protocol code does not know whether it is running through a sponge or through a real interactive exchange.

## Limitations

- **No error recovery**: mpsc disconnection (e.g., one side panics) surfaces as a `VerificationError` or a panic on `.unwrap()`. There is no retry or reconnect logic.
- **In-process only**: uses `std::sync::mpsc`, so both sides must live in the same process. Replacing mpsc with TCP or another transport would be straightforward -- the channel trait impls are ~10 lines each.
- **No transcript extraction**: unlike DSFS, there is no proof artifact produced. The live channel is for interactive execution, not for generating non-interactive proofs.
