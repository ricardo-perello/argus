# `live-channel`

`live-channel` provides in-process interactive execution for Argus protocols.

It implements `ProverChannel` and `VerifierChannel` with `std::sync::mpsc`
channels. The prover and verifier run concurrently, usually in separate
threads, and the verifier samples public coins directly.

## Basic Use

```rust
let (mut prover_ch, mut verifier_ch) = live_channel::channel_pair();

let prover_handle = std::thread::spawn(move || {
    protocol.prove(&mut prover_ch, &instance, &witness);
});

let verifier_handle = std::thread::spawn(move || {
    protocol.verify(&mut verifier_ch, &instance)
});
```

The protocol implementation is the same one used by `spongefish-dsfs`.

## Challenge Flow

In DSFS, both sides derive challenges by replaying the transcript.

In live mode, the verifier:

1. allocates the challenge representation for the requested type,
2. fills it with `OsRng`,
3. sends the raw bytes to the prover,
4. decodes the same bytes locally.

The prover receives the bytes and decodes them into the same challenge type.

## Message Flow

Prover messages are encoded by the prover and decoded by the verifier through
the channel codec traits. There is no proof string and no transcript extraction.

## Limitations

- In-process only.
- No reconnect or retry logic.
- No non-interactive proof artifact.
- Intended for authoring, testing, and demonstrations rather than deployment.
