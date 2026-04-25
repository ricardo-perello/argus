# Getting Started

Build everything:

```bash
cargo build
```

Run the full test suite:

```bash
cargo test
```

Run examples:

```bash
cargo run -p argus-examples --bin schnorr
cargo run -p argus-examples --bin schnorr -- --live
cargo run -p argus-examples --bin sumcheck
cargo run -p argus-examples --bin sumcheck_commit
cargo run -p argus-examples --bin composition
cargo run -p argus-examples --bin warp_accumulate
```

Run only WARP tests:

```bash
cargo test -p warp
```

Build local rustdoc:

```bash
cargo doc --workspace --no-deps
```

## Implementing a protocol

1. Define the public instance and private witness types.
2. Implement `InteractiveArgument` or `InteractiveReduction`.
3. Use only the channel API inside protocol code.
4. Optionally implement `ArgumentSecurity` or `ReductionSecurity`.
5. Run through `spongefish::dsfs` or `live-channel`.

Protocol code must never instantiate sponges or perform Fiat-Shamir logic.
