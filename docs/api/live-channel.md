# `live-channel`

`live-channel` provides in-process interactive execution for Argus prover and
verifier roles.

It implements `ProverChannel` and `VerifierChannel` with `std::sync::mpsc`.
The roles run concurrently, usually in separate threads, and the verifier
samples public coins directly.

## Basic Use

```rust,ignore
let (mut prover_channel, mut verifier_channel) = live_channel::channel_pair();

let prover_handle = std::thread::spawn(move || {
    argument_prover.prove(
        &mut prover_channel,
        &prover_instance,
        &witness,
    );
});

let verifier_handle = std::thread::spawn(move || {
    argument_verifier.verify(
        &mut verifier_channel,
        &verifier_instance,
    )
});
```

The prover and verifier roles are the same native roles compiled independently
by `spongefish-dsfs`.

For preprocessing execution, pass the prover key only to the prover thread and
the verifier key only to the verifier thread. Run the independent indexer before
starting either thread.

## Challenge Flow

In live mode the verifier:

1. allocates the challenge representation requested by the verifier role,
2. fills it with `OsRng`,
3. sends the encoded bytes to the prover,
4. decodes the same bytes locally.

The prover receives and decodes those bytes into the matching challenge type.

## Message Flow

Prover messages are encoded by the prover and decoded by the verifier through
the channel codec traits. There is no proof string and no transcript extraction.

## Limitations

- In-process only.
- No reconnect or retry logic.
- No non-interactive proof artifact.
- Intended for authoring, testing, and demonstrations rather than deployment.
