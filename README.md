# Argus

Argus is a Rust interface layer for public-coin interactive protocols.

Its core contribution is not a new transcript primitive. It is a clean way to
describe an interactive argument or reduction as a reusable protocol object,
without putting sponge calls or transcript logic inside the protocol itself.

Protocol authors write a conversation once against typed channels. Backends then
decide how to execute that conversation:

- `spongefish-dsfs` compiles the protocol into a non-interactive proof using the
  Duplex-Sponge Fiat-Shamir transformation.
- `live-channel` runs the same protocol interactively with verifier-sampled
  public coins.
- Future compiler work can target the same interface, for example by compiling
  an `IOP + commitment scheme` into an IA channel program before DSFS turns it
  into a NARG.

This makes the IA layer three things at once: an authoring interface, a backend
input, and a target for richer protocol compilers.

## Status

Argus is a research prototype for protocol design and security-model
experimentation. It has not received production cryptographic review.

## Model

Argus represents two protocol families:

- Interactive arguments: the verifier outputs accept or reject.
- Interactive reductions: the verifier outputs a reduced target instance.

Both are written as channel programs. Protocol code may call only:

```rust
ch.send_prover_message(&message);
let challenge = ch.read_verifier_message();

let message = ch.read_prover_message()?;
let challenge = ch.send_verifier_message();
```

The backend owns transcript mechanics: public-input binding, prover-message
absorption, challenge derivation, deterministic replay, proof byte layout, and
domain separation. Protocol code never instantiates a sponge or derives a
Fiat-Shamir challenge directly.

## Workspace

- `crates/ia-core`: protocol-facing traits, channel traits, preprocessing
  traits, non-interactive vocabulary, composition, and security metadata.
- `spongefish-dsfs`: DSFS backend used by Argus. In this workspace it is exposed
  through the patched spongefish dependency and imported as `spongefish_dsfs`.
- `crates/live-channel`: in-process interactive backend built on `mpsc`.
- `crates/argus-examples`: runnable Schnorr, sumcheck, composition, lookup, and
  WARP examples.
- `crates/warp`: WARP expressed as preprocessing reductions plus a final
  argument.
- `crates/sigma-bridge`: compatibility bridge for selected `sigma-proofs`
  layouts and vectors.

## Quickstart

```bash
cargo build
cargo test
```

Run Schnorr as a DSFS-compiled non-interactive proof:

```bash
cargo run -p argus-examples --bin schnorr
```

Run the same protocol interactively:

```bash
cargo run -p argus-examples --bin schnorr -- --live
```

Other useful examples:

```bash
cargo run -p argus-examples --bin sumcheck
cargo run -p argus-examples --bin sumcheck_commit
cargo run -p argus-examples --bin composition
cargo run -p argus-examples --bin warp_accumulate
```

Run only WARP tests:

```bash
cargo test -p warp
```

## Documentation

- [mdBook home](docs/index.md)
- [Getting started](docs/getting-started.md)
- [Architecture overview](docs/architecture/overview.md)
- [Author guide](docs/author-guide/overview.md)
- [Transcript invariants](docs/security/transcript-invariants.md)
- [API reference notes](docs/api/ia-core.md)
- [Final report](docs/final-report.md)

Build rustdoc with:

```bash
cargo doc --workspace --no-deps
```
