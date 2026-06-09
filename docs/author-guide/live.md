# Run Interactively

Native prover and verifier roles can run through `live-channel` without DSFS.

In live mode the roles execute in separate threads. The verifier samples public
coins and sends them to the prover instead of deriving them with Fiat-Shamir.

```rust,ignore
use ia_core::prelude::*;

let (mut prover_channel, mut verifier_channel) = live_channel::channel_pair();

let prover_handle = std::thread::spawn(move || {
    SchnorrProver::<G>::default().prove(
        &mut prover_channel,
        &prover_instance,
        &witness,
    );
});

let verifier_handle = std::thread::spawn(move || {
    SchnorrVerifier::<G>::default().verify(
        &mut verifier_channel,
        &verifier_instance,
    )
});

prover_handle.join().unwrap();
verifier_handle.join().unwrap()?;
```

Run the repository example both ways:

```bash
cargo run -p argus-examples --bin schnorr
cargo run -p argus-examples --bin schnorr -- --live
```

## Why Use Live Mode

Live execution checks that:

- the independently authored roles agree on message order,
- each challenge can be produced from the verifier's public view,
- protocol code does not depend on proof serialization,
- DSFS is not hiding an interaction bug.

Live mode is deliberately simple: in-process, `mpsc`-based, and without a proof
artifact.
