# WARP crate map: layers, API, and how to use it

This doc is a practical guide to **how `crates/warp` is structured and how a user is expected to use it**.

It answers:

- Where each “layer” is defined (IR/IA/composition vs concrete prover/verifier).
- What the crate **exports** as public API.
- How the integration tests instantiate WARP.
- What minimal user code looks like (both **direct channel API** and **DSFS-compiled IA/IR API**).

---

## 1) What does the `warp` crate expose?

The public API is defined by `crates/warp/src/lib.rs`, which **re-exports** the key types:

- **High-level IA-stack wrappers**
  - `WARPReduction` (an `InteractiveReduction`)
  - `WARPDeciderIA` (an `InteractiveArgument`)
  - `FullWARP` (composition: `ReducedArgument<WARPReduction, WARPDeciderIA>`)
- **Concrete protocol implementation + data types**
  - `WARP` (the struct that actually implements the prover/verifier/decider logic)
  - `WARPInstance`, `WARPWitness`
  - `DeciderInstance`, `DeciderWitness`

So users basically choose between:

- **Direct protocol API**: call methods on `WARP` (`prove_with_channel`, `verify_with_channel`, `decide`).
- **IA/IR API**: wrap state in `WARPInstance/WARPWitness`, then run `spongefish::dsfs::prove(_reduction)` / `spongefish::dsfs::verify(_reduction)` on `FullWARP` or `WARPReduction`.

---

## 2) Where each layer “lives” in the code

### Layer A — IA/IR definitions + composition (the “interface wiring” layer)

This is where WARP is expressed in the **Argus IA stack**:

- **File**: `crates/warp/src/protocol/ir.rs`
- **Defines**:
  - `WARPReduction<...>`: implements `ia_core::InteractiveReduction`
    - `prove` calls into `WARP::prove_with_channel`.
    - `verify` calls into `WARP::verify_reduction_transcript` (computes the target instance from transcript).
  - `WARPDeciderIA<...>`: implements `ia_core::InteractiveArgument`
    - `prove` sends the final codeword + witness part needed for the decider checks.
    - `verify` reconstructs and checks the final accumulated statement.
  - `FullWARP<...>`: type alias
    - `ReducedArgument<WARPReduction<...>, WARPDeciderIA<...>>`

**Mental model**: this file says “*what the protocol looks like*” in IA/IR terms and provides DSFS-friendly wrappers.

### Layer B — Concrete protocol implementation (the “actual prover/verifier code” layer)

This is where the protocol’s transcript IO and algebraic checks are implemented:

- **File**: `crates/warp/src/protocol/warp.rs`
- **Defines**:
  - `WARP<...>`: protocol parameters + methods
  - Concrete methods:
    - `prove_with_channel`
    - `verify_reduction_transcript` (transcript-only reduction verifier; computes target accumulator)
    - `verify_merkle_paths` (oracle opening checks / Merkle auth paths)
    - `verify_with_channel` (calls transcript verifier + merkle checks + compares against provided accumulator)
    - `decide` (local check of accumulated witness vs instance)
  - Instance/witness structs used by the wrappers:
    - `WARPInstance`, `WARPWitness`
    - `WARPTargetInstance/Witness`, `DeciderInstance/Witness`
  - `impl spongefish::Encoding for WARPInstance<...>` so DSFS can domain-separate on the statement.

**Mental model**: this file is “*the engine*”.

### Layer C — Subprotocol implementations (sumchecks)

These are the “inner loops” used by the reduction:

- **Twin sumcheck**
  - **File**: `crates/warp/src/protocol/twin_sumcheck.rs`
  - **Exports**: `prove`, `verify`, plus `Evals` tables.
- **Batching (inner-product) sumcheck**
  - **File**: `crates/warp/src/protocol/batching_sumcheck.rs`
  - **Exports**: `prove`, `verify`

### Layer D — Types / glue structs

These are the intermediate structs used to make phases explicit (useful for refactors and debugging):

- **File**: `crates/warp/src/types.rs`
- **Defines**:
  - Core accumulator types:
    - `AccumulatorInstances` = `(roots, alphas, mus, (taus, xs), etas)`
    - `AccumulatorWitnesses` = `(merkle_trees, codewords, witness_parts)`
  - Plus many “phase output” structs (`ParseCommitOutput`, `TwinSumcheckOutput`, etc.).

---

## 3) How do the tests instantiate and use WARP?

All end-to-end usage examples currently live in:

- **File**: `crates/warp/tests/warp_test.rs`

There are two main “user stories” shown there.

### Story 1 — Use `WARP` directly (explicit transcript channels)

The tests build a channel backed by spongefish (but **through** the channel traits):

- Prover channel: `spongefish::dsfs::SpongeProver` over a `spongefish::DomainSeparator`
- Verifier channel: `spongefish::dsfs::SpongeVerifier` replaying a `narg_string`

Then they do:

- **Prove**: `warp.prove_with_channel(&mut prover_ch, ...) -> (acc_instance, acc_witness, proof_data)`
- **Extract proof bytes**: `prover_ch.narg_string()`
- **Verify**: `warp.verify_with_channel(&mut verifier_ch, vk, &acc_instance, &proof_data)`
- **Decide**: `warp.decide(&acc_witness, &acc_instance)`

Concrete tests:

- `warp_bootstrap_prove_verify_decide`
- `warp_full_accumulation_cycle`

### Story 2 — Use the IA/IR API through DSFS (what external users likely want)

The tests also show how to use the “compiled” Argus interface:

- Construct `WARPInstance { warp: Arc<WARP>, pk, instances, acc_instances }`
- Construct `WARPWitness { witnesses, acc_witnesses }`

Then:

- **IR-only** (IOR-style): `spongefish::dsfs::prove_reduction::<WARPReduction<...>>` and `spongefish::dsfs::verify_reduction::<WARPReduction<...>>`
  - Test: `warp_ir_dsfs_prove_verify`
- **Full IA** (IR ∘ IA): `spongefish::dsfs::prove::<FullWARP<...>>` and `spongefish::dsfs::verify::<FullWARP<...>>`
  - Test: `warp_full_ia_dsfs_prove_verify`

---

## 4) What would “using the warp crate” look like?

### Option A — Direct API (if you want explicit control over transcripts/channels)

You create:

- `warp: WARP<F, P, C, MT>`
- `(pk, vk)` (relation + dimensions)
- fresh `instances/witnesses`
- current accumulator `(acc_instances, acc_witnesses)` (empty for bootstrap)
- a concrete `ProverChannel` / `VerifierChannel` implementation

Then call:

- `warp.prove_with_channel(...)`
- `warp.verify_with_channel(...)`
- `warp.decide(...)`

This is exactly what `warp_bootstrap_prove_verify_decide` does.

### Option B — IA/IR + DSFS (recommended if you want “one proof blob”)

You wrap statement/witness into:

- `WARPInstance` / `WARPWitness`

and call either:

- `spongefish::dsfs::prove_reduction::<WARPReduction<...>>()` / `spongefish::dsfs::verify_reduction::<WARPReduction<...>>()`
  - if you want the **reduced accumulator instance** as output; or
- `spongefish::dsfs::prove::<FullWARP<...>>()` / `spongefish::dsfs::verify::<FullWARP<...>>()`
  - if you want a single “accept/reject” **InteractiveArgument** (IR ∘ IA) compiled via DSFS.

This is exactly what the last two tests do.

---

## 5) “Finger map”: if you’re reading the code to understand usage

If you want to understand how everything connects (as a library user), read in this order:

1. `crates/warp/src/lib.rs`
   - What’s public (re-exports).
2. `crates/warp/tests/warp_test.rs`
   - The concrete instantiation: which types, which generics, which calls, which order.
3. `crates/warp/src/protocol/ir.rs`
   - How the protocol is packaged into `InteractiveReduction` + `InteractiveArgument` + `FullWARP`.
4. `crates/warp/src/protocol/warp.rs`
   - The actual method implementations and what messages/challenges are sent.

When you’re debugging a specific verification failure:

- `verify_reduction_transcript` tells you whether transcript/algebra checks fail.
- `verify_merkle_paths` tells you whether oracle-opening checks fail.
- `WARPDeciderIA::verify` tells you whether the final reduced statement/witness is consistent.
