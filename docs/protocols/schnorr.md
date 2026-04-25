# Schnorr Example

The Schnorr example is the smallest end-to-end IA in the workspace.

Run it non-interactively through DSFS:

```bash
cargo run -p argus-examples --bin schnorr
```

Run the same protocol interactively:

```bash
cargo run -p argus-examples --bin schnorr -- --live
```

## What It Demonstrates

- Implementing `InteractiveArgument`.
- Using only channel calls inside protocol code.
- Compiling the IA with `spongefish::dsfs`.
- Running the same IA with `live-channel`.
- Implementing constant-error `ArgumentSecurity`.

The security metadata uses:

```rust
type InstanceParams = ();
type InstanceBound = ();
```

because the tracked Schnorr error is independent of the concrete instance.
