# Argus

Argus’s main contribution is a **clean interface for public-coin interactive protocols**:

- **Interactive Arguments (IA)**: verifiers output accept/reject.
- **Interactive Reductions (IOR / IR)**: verifiers output a reduced (target) instance.

Protocols are written **once**, against a **generic channel** interface. Then, in a modular way,
you choose a backend:

- **`spongefish::dsfs`**: compile the IA/IR into a **non-interactive proof (NARG)** via the
  **Duplex-Sponge Fiat–Shamir (DSFS)** transformation (Construction 4.3 of
  _“A Fiat–Shamir Transformation from Duplex Sponges”_ (Chiesa & Orrù, 2025)).
- **`live-channel`**: run the *same* protocol **interactively** between two parties (threads via `mpsc`).

This structure ensures **protocol code never touches transcript internals**: transcript mechanics
(absorb/squeeze ordering, domain separation, deterministic replay) live in the backend.

## Project status

Argus is a research prototype. It is intended for protocol design, experimentation,
and security-model engineering; it has not received production cryptographic
review.

## Architecture

Argus aims to express:

- **DSFS[IA]**: compile a public-coin Interactive Argument (IA) into a non-interactive proof.
- **BCS[IOP, MT] = DSFS[IA]**, where **IA = IBCS[IOP, MT]** (work in progress).

The key invariants (enforced by the backend, not by protocol code) are:

- **All prover messages are absorbed before any challenge is squeezed.**
- **Public inputs are absorbed before the first challenge.**
- **Replay is deterministic.**
- **No sponge operations outside DSFS.**

## The model: “protocol as a channel program”

An IA/IR implementation is just code that exchanges typed messages with a channel:

- Prover side: `send_prover_message`, `read_verifier_message`
- Verifier side: `read_prover_message`, `send_verifier_message`

Swapping the channel swaps the execution model (DSFS-compiled vs truly interactive) without changing
the protocol.

## Crate map

- **`crates/ia-core`**: the **IA/IR interface layer**.
  - Channel traits: `ProverChannel`, `VerifierChannel`
  - NARG traits and proof artifact: `NonInteractiveArgument`, `NonInteractiveReduction`, `NargProof`
  - Protocol traits:
    - root/core traits: `ProtocolCore`, `ArgumentCore`, `ReductionCore`, `PreprocessingCore`
    - IA: `InteractiveArgument` and `PreprocessingInteractiveArgument`
    - IOR/IR: `InteractiveReduction` and `PreprocessingInteractiveReduction`
    - Security: `ArgumentSecurity` / `ReductionSecurity` (opt-in; instance-aware DSFS bound evaluation)
  - Composition:
    - `ChainedReduction` (IR ∘ IR → IR)
    - `ReducedArgument` (IR ∘ IA → IA)
- **`spongefish::dsfs`**: a **backend** that compiles IA/IR into NARGs using DSFS.
  - `plain_non_interactive_argument(body, sponge)` constructs a plain `NonInteractiveArgument`
  - `plain_non_interactive_reduction(body, sponge)` constructs a plain `NonInteractiveReduction`
  - `preprocessing_non_interactive_argument(body, sponge).prepare(&ix)` constructs a prepared preprocessing NARG
  - `preprocessing_non_interactive_reduction(body, sponge).prepare(&ix)` constructs a prepared preprocessing reduction NARG
  - DSFS security bound evaluation (Theorems 1 & 2 style bounds)
- **`crates/live-channel`**: a **backend** that runs IA/IR interactively (prover/verifier in threads via `mpsc`).
- **`crates/warp`**: a WARP (ePrint 2025/753) implementation expressed as:
  - `WARPReduction` (a `PreprocessingInteractiveReduction`)
  - `WARPDeciderIA` (a `PreprocessingInteractiveArgument`)
  - `FullWARP = ReducedArgument<WARPReduction, WARPDeciderIA>`
- **`crates/argus-examples`**: runnable examples (e.g. Schnorr).
- **`crates/ibcs`**: WIP — will implement the IOP-to-IA compiler (BCS[IOP, MT] = DSFS[IBCS[IOP, MT]]).

## Documentation index

The documentation is organized as an mdBook-compatible tree:

- **Start here**: `docs/index.md` and `docs/getting-started.md`
- **Architecture**: `docs/architecture/overview.md`, `docs/architecture/channel-model.md`,
  `docs/architecture/ia-ir.md`, `docs/architecture/backends.md`
- **Security**: `docs/security/overview.md`, `docs/security/transcript-invariants.md`,
  `docs/security/instance-aware-security.md`, `docs/security/rbr-and-sr.md`,
  `docs/security/dsfs-bounds.md`, `docs/security/domain-separation.md`
- **API**: `docs/api/ia-core.md`, `docs/api/spongefish-dsfs.md`, `docs/api/live-channel.md`
- **Protocols**: `docs/protocols/schnorr.md`, `docs/protocols/sumcheck.md`,
  `docs/protocols/warp.md`, `docs/protocols/sigma-bridge.md`
- **Decisions and history**: `docs/adr/README.md` and `docs/history/README.md`
- **Contribution process**: `CONTRIBUTING.md`

Versioned design notes such as `iarg-interface-v1.md` through
`iarg-interface-v6.md` are preserved under `docs/history/` so design history is
readable without Git archaeology.

For API-level documentation, prefer rustdoc on the crate that owns the API:

```bash
cargo doc --workspace --no-deps
```

## Quickstart

Build everything:

```bash
cargo build
```

Run the full test suite (includes WARP integration tests):

```bash
cargo test
```

Run Schnorr via DSFS (non-interactive proof):

```bash
cargo run -p argus-examples --bin schnorr
```

Run Schnorr interactively (live prover/verifier threads):

```bash
cargo run -p argus-examples --bin schnorr -- --live
```

Run a few other runnable examples:

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

## How to implement a new protocol

At a high level:

1. Define your statement/witness types in some crate.
2. Use `ia_core::impl_interactive_argument!` or
   `ia_core::impl_interactive_reduction!` to write one authoring block.
3. Put only channel operations inside `prove`/`verify`.
4. Compile it non-interactively with `spongefish_dsfs::plain_non_interactive_argument(body, sponge)` or `spongefish_dsfs::plain_non_interactive_reduction(body, sponge)`.

For preprocessing protocols, use
`spongefish_dsfs::preprocessing_non_interactive_argument(body, sponge).prepare(&ix)`
or `spongefish_dsfs::preprocessing_non_interactive_reduction(body, sponge).prepare(&ix)`.

The macros expand to the explicit inheritance tree underneath:
`ProtocolCore` plus `ArgumentCore`/`ReductionCore`, then the executable
`Interactive*` trait. Manual impls still work when tests or low-level adapters
are clearer that way.

For a preprocessed protocol, use `ia_core::impl_preprocessing_argument!` or
`ia_core::impl_preprocessing_reduction!`. Those blocks include `Index`,
`ProverKey`, `VerifierKey`, and `index(ix) -> (pk, vk)`, then DSFS calls
`.prepare(&ix)` before proving/verifying.

Protocol code should only ever call:

- `ch.send_prover_message(...)`
- `ch.read_prover_message(...)`
- `ch.send_verifier_message(...)`
- `ch.read_verifier_message(...)`

…never sponge operations directly.
