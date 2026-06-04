# Schnorr

The Schnorr example is the smallest end-to-end interactive argument in the
workspace.

It proves knowledge of `x` such that:

```text
X = x * G
```

The plain relation is:

```text
Instance = (G, X)
Witness  = x
```

Run it non-interactively through DSFS:

```bash
cargo run -p argus-examples --bin schnorr
```

Run the same protocol interactively:

```bash
cargo run -p argus-examples --bin schnorr -- --live
```

## What It Demonstrates

- one `ia_core::impl_interactive_argument!` block,
- channel-only prover and verifier logic,
- DSFS compilation with `spongefish_dsfs::plain_non_interactive_argument`,
- live execution with `live-channel`,
- constant-error `ArgumentSecurity`.

The security metadata uses:

```rust
type InstanceParams = ();
type InstanceBound = ();
```

because the tracked Schnorr error is independent of the concrete instance.
