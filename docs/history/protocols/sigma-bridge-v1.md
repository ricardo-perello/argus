# sigma-bridge: Sigma → IA → DSFS

This document describes how `crates/sigma-bridge` turns a `sigma-proofs` [`SigmaProtocol`] into a **non-interactive proof** by driving it through the Argus **Interactive Argument (IA)** channel interface and the **DSFS** compiler.

The key outcome is:

- The proof is the **full spongefish NARG string**, containing **commitment(s) then response(s)**.
- All prover messages are sent via the IA channel (`send_prover_message`) and therefore are **absorbed and appended** to the NARG string.

This is intentionally **not byte-identical** to `sigma-proofs::Nizk`, which uses `public_message` for commitments (absorb-only) and then manually prepends commitment bytes to the returned proof.

## Goals and non-goals

- **Goal**: Use the Argus architecture strictly: **sigma → IA → DSFS**, with transcript logic centralized in DSFS.
- **Goal**: Preserve DSFS invariants (e.g. all prover messages absorbed before squeezing challenges).
- **Non-goal**: Byte-identical compatibility with `sigma-proofs::Nizk` proof strings.
- **Non-goal**: Compact proofs (batchable only).

## High-level flow

Given a sigma protocol `P: SigmaProtocol` (3-message structure):

1. Prover computes commitment(s): `protocol.prover_commit(...) -> (commitment, ip_state)`.
2. Prover sends each commitment element through the IA channel:
   - `ProverChannel::send_prover_message(&commitment[i])`
3. Prover reads the verifier challenge from the channel:
   - `ProverChannel::read_verifier_message::<P::Challenge>()`
4. Prover computes response(s): `protocol.prover_response(ip_state, &challenge)`.
5. Prover sends each response element through the IA channel:
   - `ProverChannel::send_prover_message(&response[i])`
6. The proof bytes returned are the channel’s **NARG string**.

Verifier mirrors this:

1. Reads `commitment_len()` prover messages from the proof NARG string.
2. Squeezes the challenge (same transcript state).
3. Reads `response_len()` prover messages from the proof NARG string.
4. Checks EOF (no trailing bytes).
5. Runs `protocol.verifier(&commitment, &challenge, &response)`.

## Why this differs from `sigma-proofs::Nizk`

`sigma-proofs::Nizk::prove_batchable` uses spongefish’s `public_message` for commitments:

- `public_message(bytes)` **absorbs** into transcript state but **does not append** to the NARG string.
- The proof bytes are then assembled manually as:
  - `commitment_bytes || response_bytes`

In contrast, Argus’s IA channel method `send_prover_message` is defined to represent a **prover message in the transcript**, so it must be:

- **absorbed**, and
- **recorded in the NARG string** (for deterministic replay).

That is why `sigma-bridge`’s proof bytes differ: commitment bytes are produced by spongefish’s `prover_message` serialization (via `NargSerialize`), not “manually concatenated bytes that were only absorbed”.

## Domain separation and session

`sigma-bridge` uses spongefish’s `DomainSeparator`:

- `protocol_identifier()` goes into `DomainSeparator::new(...)`
- A 64-byte session field is derived via `sigma_bridge::derive_session_id(session_id)`
- The protocol’s `instance_label()` is used as the `instance(...)` label

Then the DSFS channel is instantiated as:

- Prover: `domsep.to_prover(sponge)`
- Verifier: `domsep.to_verifier(sponge, proof_bytes)`

The sponge is caller-chosen (e.g. `dsfs::Keccak::default()` or `dsfs::StdHash::default()`).

## API (current)

The primary entry points are:

- `sigma_bridge::prove(sponge, session_id, protocol, witness, rng) -> Vec<u8>`
- `sigma_bridge::verify(sponge, session_id, protocol, proof_bytes) -> Result<(), Error>`

Both functions are generic over the duplex sponge `H` as long as it is byte-oriented (`dsfs::ByteDuplexSponge`).

## Minimal example

This sketch shows how to call the bridge (types omitted for brevity):

```rust
let mut rng = /* ScalarRng */;
let proof = sigma_bridge::prove(
    dsfs::Keccak::default(),
    b"session",
    &protocol,
    &witness,
    &mut rng,
)?;

sigma_bridge::verify(
    dsfs::Keccak::default(),
    b"session",
    &protocol,
    &proof,
)?;
```

## Testing notes

The tests in `crates/sigma-bridge/tests/` focus on **round-trip correctness** (prove then verify), not golden-vector byte equality:

- Round-trip tests validate the **pure IA transcript layout**.
- Some σ-proofs JSON vector parsing for P-256 may fail upstream (`CanonicalLinearRelation::from_label`), and such cases are currently skipped/ignored until resolved.

