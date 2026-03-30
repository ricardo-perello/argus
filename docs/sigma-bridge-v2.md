# sigma-bridge-v2: byte-identical σ-proofs batchable proofs

This document describes the **v2 behavior** of `crates/sigma-bridge`: driving a `sigma-proofs` [`SigmaProtocol`] through the Argus **Interactive Argument (IA)** channel interface and the **DSFS** compiler while producing **byte-for-byte identical** proofs to `sigma-proofs::Nizk::prove_batchable`.

## Goals and non-goals

- **Goal**: Proof bytes are **byte-identical** to `sigma-proofs::Nizk::prove_batchable`.
- **Goal**: Keep Argus architecture strict: **sigma → IA → DSFS**, with **transcript logic centralized in DSFS**.
- **Goal**: Preserve DSFS invariants (e.g. absorb all prover messages that must influence a challenge **before** squeezing that challenge).
- **Non-goal**: Compact proofs (this bridge targets the **batchable** proof format).

## Proof format (byte layout)

The batchable proof bytes are:

- `commitment_bytes_prefix || response_narg_bytes`

where:

- **Commitments** are encoded as σ-proofs expects (via `Encoding::encode()` for each commitment element) and **absorbed** into the Fiat–Shamir transcript via spongefish `public_message` (**absorb-only**, not appended to the NARG string).
- **Responses** are sent through the IA channel as prover messages (`send_prover_message`), which **absorbs** and also **appends** to the spongefish **NARG string**. The NARG string portion of the proof contains **responses only**.

## High-level flow (sigma → IA → DSFS)

Given a sigma protocol `P: SigmaProtocol`:

### Prover

1. Compute commitment(s): `protocol.prover_commit(...) -> (commitment, ip_state)`.
2. For each commitment element `c`:
   - Absorb `c` into the transcript via DSFS channel `public_message(c)` (**absorb-only**).
   - Append `c.encode()` to the proof’s **commitment prefix** buffer.
3. Squeeze the verifier challenge: `read_verifier_message::<P::Challenge>()`.
4. Compute response(s): `protocol.prover_response(ip_state, &challenge)`.
5. For each response element `r`:
   - Send via `send_prover_message(r)` (**absorb + append to NARG**).
6. Output proof bytes: `commitment_prefix || narg_string()` (responses-only NARG).

### Verifier

1. Parse `commitment_len()` commitment elements from the **prefix** of the proof bytes.
2. Initialize the DSFS verifier channel over the **remaining bytes** (the responses-only NARG).
3. For each parsed commitment element `c`:
   - Absorb via `public_message(&c)` (**absorb-only**).
4. Squeeze the verifier challenge: `send_verifier_message::<P::Challenge>()`.
5. Read `response_len()` responses from the NARG via `read_prover_message`.
6. Check EOF on the NARG (no trailing bytes).
7. Run `protocol.verifier(&commitment, &challenge, &response)`.

## Domain separation and session

`sigma-bridge` uses spongefish `DomainSeparator` exactly as before:

- `protocol_identifier()` goes into `DomainSeparator::new(...)`
- A 64-byte session field is derived via `sigma_bridge::derive_session_id(session_id)`
- The protocol’s `instance_label()` is used as the `instance(...)` label

This ensures transcript replay is deterministic and matches σ-proofs’ session derivation.

## Where transcript logic lives (and does not live)

- **Lives in DSFS**: sponge absorption/squeezing via `SpongeProver` / `SpongeVerifier` (`crates/dsfs/src/channel.rs`), including the distinction between:
  - `public_message` (absorb-only), and
  - `send_prover_message` (absorb + append-to-NARG).
- **Does not live in sigma protocol code**: `SigmaProtocol` implementations remain unaware of Fiat–Shamir and NARG encoding details.
- **sigma-bridge responsibility**: assembling and parsing the *proof byte string layout* (`commitment_prefix || response_narg`) while using DSFS channel adapters for all sponge operations.

## Testing

`crates/sigma-bridge/tests/golden_vectors.rs` asserts **byte equality** between:

- `sigma_bridge::prove(...)`
- and the JSON golden fields (`"Batchable Proof"` for SHAKE128 vectors, `"proof_batchable"` for Keccak vectors)

alongside a normal `sigma_bridge::verify(...)` check for each vector.

