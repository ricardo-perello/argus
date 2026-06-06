# Run Interactively

The same `InteractiveArgument` can run with a live backend.

In live mode, prover and verifier execute in separate threads over channels.
The verifier samples public coins and sends them to the prover instead of
deriving them with Fiat-Shamir.

```rust
use ia_core::prelude::*;   // prove()/verify() live on the role half-traits

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

Run the example both ways:

```bash
cargo run -p argus-examples --bin schnorr
cargo run -p argus-examples --bin schnorr -- --live
```

## Why Use Live Mode

Live execution is useful while authoring because it checks that the protocol
really has a public-coin interaction shape:

- prover and verifier agree on message order,
- each verifier challenge can be produced from the verifier's public view,
- protocol code does not depend on proof serialization,
- DSFS is not hiding an interaction bug.

Live mode is deliberately simple. It is in-process, uses `mpsc`, and produces no
proof artifact.
