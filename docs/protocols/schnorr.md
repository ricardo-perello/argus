# Schnorr

The Schnorr example is the smallest end-to-end role-first argument in the
workspace. It proves knowledge of `x` such that:

```text
X = x * G
```

```text
Instance = (G, X)
Witness  = x
```

Run it through DSFS:

```bash
cargo run -p argus-examples --bin schnorr
```

Run the same conversation interactively:

```bash
cargo run -p argus-examples --bin schnorr -- --live
```

## Roles

The implementation defines:

- `SchnorrProver<G>` with `Instance`, `Witness`, and `prove`.
- `SchnorrVerifier<G>` with `Instance` and `verify`.

They are authored together with `impl_interactive_argument!`. The macro emits
separate native implementations, routing the witness and `prove` only to the
prover while the verifier keeps no witness capability.

DSFS compiles them with:

```rust,ignore
let prover = spongefish_dsfs::plain_non_interactive_argument_prover(
    SchnorrProver::<G>::default(),
    spongefish_dsfs::Keccak::default(),
);
let verifier = spongefish_dsfs::plain_non_interactive_argument_verifier(
    SchnorrVerifier::<G>::default(),
    spongefish_dsfs::Keccak::default(),
);
```

The same native roles run over `live-channel`.

## Security Metadata

`ArgumentSecurity` is implemented on `SchnorrVerifier<G>`. Its tracked soundness
error is independent of the concrete instance, so both `InstanceParams` and
`InstanceBound` are `()`.
