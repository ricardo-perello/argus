# Argus

Argus’s main contribution is a **clean interface for public-coin interactive protocols**:

- **Interactive Arguments (IA)**: verifiers output accept/reject.
- **Interactive Reductions (IOR / IR)**: verifiers output a reduced (target) instance.

Protocols are written **once**, against a **generic channel** interface. Then, in a modular way,
you choose a backend:

- **`dsfs`**: compile the IA/IR into a **non-interactive proof (NARG)** via the
  **Duplex-Sponge Fiat–Shamir (DSFS)** transformation (Construction 4.3 of
  _“A Fiat–Shamir Transformation from Duplex Sponges”_ (Chiesa & Orrù, 2025)).
- **`live-channel`**: run the *same* protocol **interactively** between two parties (threads via `mpsc`).

This structure ensures **protocol code never touches transcript internals**: transcript mechanics
(absorb/squeeze ordering, domain separation, deterministic replay) live in the backend.

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
  - Protocol traits:
    - IA: `InteractiveArgument` (with generic `prove` / `verify` methods)
    - IOR/IR: `InteractiveReduction` (with generic `prove` / `verify` methods)
    - Security: `ProtocolSecurity` (opt-in; enables DSFS security bound evaluation)
  - Composition:
    - `ChainedReduction` (IR ∘ IR → IR)
    - `ReducedArgument` (IR ∘ IA → IA)
- **`spongefish::dsfs`**: a **backend** that compiles IA/IR into NARGs using DSFS.
  - `prove` / `verify` for IAs
  - `prove_reduction` / `verify_reduction` for IORs
  - DSFS security bound evaluation (Theorems 1 & 2 style bounds)
- **`crates/live-channel`**: a **backend** that runs IA/IR interactively (prover/verifier in threads via `mpsc`).
- **`crates/warp`**: a WARP (ePrint 2025/753) implementation expressed as:
  - `WARPReduction` (an `InteractiveReduction`)
  - `WARPDeciderIA` (an `InteractiveArgument`)
  - `FullWARP = ReducedArgument<WARPReduction, WARPDeciderIA>`
- **`crates/argus-examples`**: runnable examples (e.g. Schnorr).
- **`crates/ibcs`**: WIP — will implement the IOP-to-IA compiler (BCS[IOP, MT] = DSFS[IBCS[IOP, MT]]).

## Documentation index

- **IA/IR interface**: `docs/iarg-interface-v5.md` — current trait design, protocol id scheme, security metadata
- **Domain separation**: `docs/domain-separation.md` — `derive(protocol, sponge_info, session)`, `SpongeInfo`, σ-proofs alignment
- **DSFS compiler**: `docs/dsfs-v2.md` — Keccak transcript, salt, sponge parameters
- **Interactive reductions**: `docs/interactive-reduction-v2.md` — sequential composition, source/target witness
- **Sigma bridge**: `docs/sigma-bridge-v3.md` — StdHash vs Keccak, golden vector behavior
- **WARP**: `docs/warp.md` — protocol overview; `docs/examples-vs-warp.md` — API layers and usage guide
- **Live channel**: `docs/live-channel.md`

Prior interface iterations and the April 2026 domain-separation **planning** write-up are in `docs/archive/`.

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
2. Implement `InteractiveArgument` (or `InteractiveReduction`) **against the channel traits** from `ia-core`.
3. Compile it non-interactively with `spongefish::dsfs::prove` / `spongefish::dsfs::verify` (or the reduction variants).

Protocol code should only ever call:

- `ch.send_prover_message(...)`
- `ch.read_prover_message(...)`
- `ch.send_verifier_message(...)`
- `ch.read_verifier_message(...)`

…never sponge operations directly.
