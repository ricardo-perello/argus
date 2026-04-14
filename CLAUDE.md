## Project: Argus (Rust workspace)

Argus implements a clean interface for **public-coin interactive protocols**:

- **Interactive Arguments (IA)**: verifiers output accept/reject.
- **Interactive Reductions (IOR / IR)**: verifiers output a reduced (target) instance.

Protocols are written once against a **generic channel interface** and then executed via a backend:

- `dsfs`: compile IA/IR into a **non-interactive proof (NARG)** via **Duplex-Sponge Fiat–Shamir (DSFS)** (Construction 4.3 of Chiesa & Orrù, 2025).
- `live-channel`: run the same protocol **interactively** (threads via `mpsc`).

**Protocol code must never touch transcript internals**. All transcript mechanics (absorb/squeeze ordering, domain separation, deterministic replay) are owned by the backend (primarily `crates/dsfs`).

---

## How to run (golden commands)

- Build: `cargo build`
- Typecheck: `cargo check`
- Test all: `cargo test`
- Run examples:
  - DSFS Schnorr (non-interactive): `cargo run -p argus-examples --bin schnorr`
  - Live Schnorr (interactive): `cargo run -p argus-examples --bin schnorr -- --live`
  - Other examples:
    - `cargo run -p argus-examples --bin sumcheck`
    - `cargo run -p argus-examples --bin sumcheck_commit`
    - `cargo run -p argus-examples --bin composition`
    - `cargo run -p argus-examples --bin warp_accumulate`
- Run only WARP tests: `cargo test -p warp`

Definition of done for changes:

- `cargo test` passes (or a narrower, explicitly stated scope passes).
- No changes to transcript ordering unless the change is explicitly justified and reviewed against Construction 4.3.

---

## Repo map (start reading here)

- `crates/ia-core`: IA/IOR interfaces and channel traits. **Protocol code depends on this only.**
- `crates/dsfs`: DSFS compiler backend. **This is the only layer allowed to touch the sponge/transcript.**
- `crates/live-channel`: interactive backend (verifier samples randomness and sends it to prover).
- `crates/warp`: WARP expressed as `InteractiveReduction` + `InteractiveArgument`, composed via `ReducedArgument`.
- `crates/sigma-bridge`: drives `sigma-proofs` sigma protocols through the IA→DSFS pipeline (compatibility-oriented).
- `crates/argus-examples`: runnable examples (Schnorr, sumcheck, composition, WARP demos).
- `docs/`: DSFS notes, IA interface iterations, reductions, WARP overview.

Useful docs:

- `README.md` (overview + quickstart)
- `docs/dsfs-v2.md` (Keccak transcript, optional salt, sponge params)
- `docs/iarg-interface-v4.md` (security metadata + DSFS bounds)
- `docs/warp.md` (how WARP plugs into Argus)
- `docs/live-channel.md` (interactive execution model)

---

## Non-negotiable cryptographic invariants (DO NOT VIOLATE)

These are global correctness requirements. When making changes, explicitly check each one:

1. All prover messages must be absorbed before any challenge is squeezed.
2. Public inputs must be absorbed before the first challenge.
3. Transcript replay must be deterministic.
4. No challenge may be reused across rounds.
5. No implicit state mutation is allowed outside the transcript/channel.
6. All transcript operations must be explicit.
7. Absorb/squeeze ordering must follow DSFS Construction 4.3 exactly.
8. No cryptographic logic may be duplicated across modules.
9. The IA abstraction must not depend on transcript internals.
10. DSFS must be the only place where sponge operations occur.

Notes:

- “**Public inputs**” here means **everything that must be fixed before the first challenge** (at minimum: protocol id / domain separator inputs, session id, and instance label/bytes). Protocol code should *not* implement this absorption itself; backends must.

---

## Architectural rules (protocol authors)

Protocol implementations must only use the channel API:

- Prover side: `send_prover_message`, `read_verifier_message`
- Verifier side: `read_prover_message`, `send_verifier_message`

Protocol code must NOT:

- instantiate sponges
- call spongefish transcript methods directly
- reorder prover-message absorption vs. challenge derivation
- perform any Fiat–Shamir logic outside the backend

If you need transcript changes, change `crates/dsfs` (and update any compatibility paths deliberately).

---

## DSFS transcript sponge choice (Argus standard vs spongefish “std”)

Be careful with the word “default”:

- **Argus standard (project default)**: **Keccak** transcript sponge. This is the default for `dsfs::prove/verify` and matches the DSFS paper’s analyzed setting used by this repo.
- **spongefish `std_prover/std_verifier`**: **`StdHash` (SHAKE128)** bootstrap. This is spongefish’s “standard hash transcript” construction and is used in Argus **only when explicitly selecting `StdHash`** for compatibility with external layouts (notably σ-proofs batchable proofs and some existing vector formats).

---

## Protocol id / domain separation (rule of thumb)

The 64-byte `protocol_id` absorbed into the spongefish `DomainSeparator` must tag the **compiled NARG/transcript format**, not only the underlying IA.

- If you change **sponge choice**, **salt policy**, or transcript/NARG layout, the DSFS-level `protocol_id` must change too.
- If you’re matching an external format, the external “ciphersuite”/protocol tag may *not* equal the IA’s own identifier; treat it as a DSFS-level input.

---

## σ-proofs vectors (sigma-bridge golden tests)

- The Shake128 σ-proofs fixtures (`sigma-proofs_Shake128_*.json`) are asserted **byte-for-byte** in `crates/sigma-bridge/tests/golden_vectors.rs` when using `StdHash`.
- Some Keccak/OWKeccak-named JSON files are **not** enforced by `sigma-proofs` Rust tests (some are only **checksum-pinned** upstream). Do not assume “file exists in testdata” implies “`cargo test` checks it”.

---

## Session derivation (must match σ-proofs)

`sigma_bridge::derive_session_id` uses **SHAKE128** with domain `fiat-shamir/session-id`, and writes output into the **high 32 bytes** of a 64-byte session field. Do not “simplify” this.

---

## Where to change what (quick checklist)

- **Change absorb/squeeze ordering or transcript semantics**: only `crates/dsfs` (and re-check Construction 4.3 + invariants).
- **Interop / external vector matching**: typically `crates/sigma-bridge` + `dsfs` transcript init (`TranscriptSponge`) and protocol-id wiring.
- **Add a new protocol**: implement it against `crates/ia-core` channel traits only; do not touch sponges/transcripts in protocol code.

---

## Transcript review checklist (fast, practical)

When reviewing any change that touches protocol execution or transcript wiring, verify:

- The protocol/backends follow the per-round shape: **absorb all prover messages → squeeze challenge**.
- No challenge is squeezed until all prover messages for that round are absorbed.
- Any change to transcript layout / sponge choice / salt policy triggers a `protocol_id` review (see “Protocol id / domain separation”).
- `verify(...)` consumes exactly the expected proof bytes (EOF check, no trailing data).

---

## Working style (safe by default)

- Start by reading and summarizing relevant code and which invariants apply.
- Propose a minimal diff plan before editing.
- Prefer the smallest change that preserves transcript ordering and determinism.
- Do not add dependencies or change crypto primitives without calling it out explicitly.
- Always provide a concrete test plan (which `cargo ...` commands to run).
- Never add a `Co-Authored-By: Claude ...` trailer to commit messages.

## Advisors on the project

- Im working directly under Alessandro Chiesa and Michele Orru. 
- Alessandro will give me ideas about where the project could go in a more general direction and sometimes will ask for things that are unfeasable in rust, its ok to challenge those ideas from a technical perspective.
- Michele is much more technical and a really good rust dev, so we can usually just apply what he says.