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
2. Implement `ProtocolBody` plus `ArgumentBody` or `ReductionBody`.
3. Implement `InteractiveArgument` or `InteractiveReduction`.
4. Use only the channel API inside protocol code.
5. Optionally implement `ArgumentSecurity` or `ReductionSecurity`.
6. Run through `spongefish::dsfs` or `live-channel`.

DSFS construction is explicit:

```rust
let nia = spongefish_dsfs::non_interactive_argument(body, spongefish_dsfs::Keccak::default());
let proof = nia.prove(&session, &instance, &witness);
nia.verify(&session, &instance, &proof)?;
```

For preprocessed protocols, implement `IndexedBody` plus
`IndexedInteractiveArgument` or `IndexedInteractiveReduction`, then prepare the
DSFS wrapper:

```rust
let nia = spongefish_dsfs::non_interactive_argument(indexed_body, sponge)
    .prepare(&index);
```

Protocol code must never instantiate sponges or perform Fiat-Shamir logic.
