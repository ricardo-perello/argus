# Run Interactively

The same `InteractiveArgument` can run with a live backend.

In live mode, prover and verifier execute in separate threads over channels. The
verifier samples public coins and sends them to the prover instead of deriving
them with Fiat-Shamir.

```rust
let (mut prover_ch, mut verifier_ch) = live_channel::channel_pair();

let prover_handle = std::thread::spawn(move || {
    Schnorr::<G>::default().prove(&mut prover_ch, &instance, &witness);
});

let verifier_handle = std::thread::spawn(move || {
    Schnorr::<G>::default().verify(&mut verifier_ch, &instance)
});

prover_handle.join().unwrap();
verifier_handle.join().unwrap()?;
```

The full Schnorr example exposes both modes:

```bash
cargo run -p argus-examples --bin schnorr
cargo run -p argus-examples --bin schnorr -- --live
```

## Why Use Live Mode

Live execution is useful while authoring because it checks the protocol as an
actual public-coin conversation:

- The prover and verifier agree on message order.
- The verifier can produce each challenge from its local view.
- The protocol body does not rely on proof serialization.
- The DSFS path is not hiding an interaction bug.

Once live execution is correct, DSFS should be able to compile the same channel
program into a NARG without changing the protocol body.

## What Stays Backend-Owned

Even live mode does not give protocol code direct access to transport internals.
The protocol still sends and receives typed messages through `ProverChannel` and
`VerifierChannel`.

That is the design point: the protocol describes the conversation, not the
mechanism.
