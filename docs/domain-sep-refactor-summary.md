# Domain Separation Refactor — Before / After

Reference for the Michele conversation. Shows what changed across **spongefish**, **Argus (dsfs + sigma-bridge)**, and **sigma-proofs** — old state on the left, new state on the right.

There are two phases:
1. **Phase 1** — `DomainSeparator::derive` API (spongefish 0.7.0): replace raw concatenation with a proper SHA-512 keyed derivation, surface `sponge_info` as an explicit field.
2. **Phase 2** — Sponge-agnostic protocol identifiers: remove the embedded sponge name from `protocol_identifier()` so the ID describes the math only.

---

## spongefish

### Version


| Before | After                                                 |
| ------ | ----------------------------------------------------- |
| 0.6.0  | 0.7.0 (breaking API change — `new`/`session` removed) |


### `DomainSeparator` constructor


| Before                                                         | After                                                                                          |
| -------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `DomainSeparator::new([u8; 64]).session(session).instance(&x)` | `DomainSeparator::derive(protocol_id: &[u8], sponge_info: &[u8], session: &[u8]).instance(&x)` |


The old `new` + `session` + `without_session` methods are removed entirely. `derive` is the only constructor.

### Cryptographic derivation


| Before                                                                                                                                     | After                                                                                                                    |
| ------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------ |
| Raw concatenation: `protocol[64] || session[64] || instance` absorbed as sequential `public_message` calls. No hashing, no length framing. | SHA-512 over `LE32(|p|)||p || LE32(|i|)||i || LE32(|s|)||s` → 64-byte `domsep`. Then `domsep` absorbed, then `instance`. |


### How `domsep` enters the sponge


| Before                                                                              | After                                                                                   |
| ----------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `protocol[64]` → `session[64]` → `instance` (three separate `public_message` calls) | `domsep[64]` → `instance` (two calls; session and sponge_info are folded into `domsep`) |


### `DomainSeparator` struct


| Before                                                                         | After                                                                                                |
| ------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------- |
| `DomainSeparator<I, S>` — two type parameters (instance state + session state) | `DomainSeparator<I>` — one type parameter; `pub domsep: [u8; 64]` field                              |
| No `#[derive]` documented (had `Debug, Copy, Clone` on inner types)            | `#[derive(Debug, Clone, Copy)]` on `DomainSeparator<I>`, `WithoutInstance<I>`, `WithInstance<'i, I>` |
| `WithInstance<I>(I)` — owned instance                                          | `WithInstance<'i, I: ?Sized>(&'i I)` — borrowed; enables unsized instances (`[u8]`, `str`)           |


### `domain_separator!` macro


| Before                                                              | After                                                                                                |
| ------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `domain_separator!("proto").session(session!("sess")).instance(&x)` | `domain_separator!("proto"; "sess").instance(&x)`                                                    |
| Protocol bytes: `protocol_id(...)` → zero-padded to 64 bytes        | Protocol bytes: `protocol_label(...)` → unpadded UTF-8                                               |
| `sponge_info` not a concept                                         | Default `sponge_info = DOMAIN_SEPARATOR_MACRO_SPONGE_INFO = b"spongefish/domain_separator/macro/v1"` |


### New: `DomainSeparatorPrefix`

Not present before. Precomputes the `(protocol_id, sponge_info)` SHA-512 prefix once; `with_session(session)` finishes the hash per proof. Useful when protocol and sponge are fixed but session varies per call.

---

## Argus — `ia-core`

### `InteractiveArgument::protocol_id`


| Before                                              | After                                                                                 |
| --------------------------------------------------- | ------------------------------------------------------------------------------------- |
| `fn protocol_id() -> [u8; 32]` — static, no `&self` | `fn protocol_id(&self) -> impl AsRef<[u8]>` — instance method, variable-length output |
| `fn prove<P>(ch, instance, witness)` — static       | `fn prove<P>(&self, ch, instance, witness)` — takes `&self`                           |
| `fn verify<V>(ch, instance)` — static               | `fn verify<V>(&self, ch, instance)` — takes `&self`                                   |


This unblocks runtime-determined identifiers (e.g. `ComposedRelation` hashing its composition tree).

---

## Argus — `dsfs`

### `compile.rs` — transcript initialization


| Before                                                                                                                                   | After                                                                                        |
| ---------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `protocol_id` (32 bytes) concatenated with sponge tag (32 bytes) into `[u8; 64]`, then `DomainSeparator::new([u8; 64]).session(session)` | `DomainSeparator::derive(ia.protocol_id().as_ref(), H::SPONGE_INFO, session_bytes.as_ref())` |
| Session: `[u8; 64]` fixed-size array                                                                                                     | Session: `session.encode()` — any `S: Encoding<[u8]>`                                        |


### `params.rs` — `SpongeInfo` constants (new)

```rust
impl SpongeInfo for Keccak  { const SPONGE_INFO: &'static [u8] = b"dsfs/v2/keccak-f1600-r136c64"; }
impl SpongeInfo for StdHash { const SPONGE_INFO: &'static [u8] = b"dsfs/v2/shake128-r168c32"; }
```

These are the `sponge_info` field in every `derive` call. Must change if sponge shape or DSFS layout changes.

---

## Argus — `sigma-bridge`

### `transcript_protocol_id` removed — Phase 2

`fiat_shamir.rs` previously had a `transcript_protocol_id<P, H>` function that remapped `"sigma-proofs_Shake128_BLS12381"` → `"sigma/OWKeccak1600+Bls12381"` when using Keccak, to paper over the sponge name embedded in the old protocol ID.

With sponge-agnostic IDs there is nothing to remap. `prove()` and `verify()` now call `protocol.protocol_identifier()` directly.

### Golden vectors

All four golden-vector tests pass with no `#[ignore]`:
- `golden_bls12381_stdhash` — pins sigma-proofs byte compatibility (StdHash)
- `golden_p256_stdhash` — same for P-256
- `golden_bls12381_keccak` — regenerated for spongefish 0.7.0 (`prove_with_protocol_domain`, explicit ciphersuite domain)
- `prove_with_protocol_domain_matches_inlined_nizk_prove_batchable` — structural consistency check

### New test: `composed_relation_smoke`

Round-trip for `SigmaIA<ComposedRelation<G>>` through DSFS, confirming the variable-length `protocol_id` path works end-to-end.

---

## sigma-proofs

### Dependency


| Before                          | After                                                                                           |
| ------------------------------- | ----------------------------------------------------------------------------------------------- |
| `spongefish = "0.5"` (registry) | `spongefish = "0.7.0"` + `[patch.crates-io] spongefish = { path = "../spongefish/spongefish" }` |


### `Nizk` transcript initialization (`src/fiat_shamir.rs`)


| Before                                                                                                   | After                                                                                                                     |
| -------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `DomainSeparator::new(protocol_id).session(derive_session_id(session_id)).instance(&label).std_prover()` | `DomainSeparator::derive(protocol_id.as_ref(), DSFS_STDHASH_SPONGE_INFO, session.as_ref()).instance(&label).std_prover()` |


New constant added:

```rust
const DSFS_STDHASH_SPONGE_INFO: &[u8] = b"dsfs/v2/shake128-r168c32";
// must stay byte-identical to dsfs::params::StdHash::SPONGE_INFO
```

This makes `Nizk::prove_batchable` and `sigma_bridge::prove` produce identical bytes for the same inputs.

### Protocol identifier cleanup (`src/schnorr_protocol.rs`) — Phase 2

`SigmaProtocol::protocol_identifier()` no longer embeds the sponge name:

| Before | After |
| ------ | ----- |
| `b"sigma-proofs_Shake128_BLS12381"` | `b"sigma-proofs/linear-relation/BLS12381"` |
| `b"sigma-proofs_Shake128_P256"` | `b"sigma-proofs/linear-relation/P256"` |
| `b"ietf sigma proof linear relation"` | `b"sigma-proofs/linear-relation"` |

The protocol identifier now describes the **math** only (a linear relation over a specific group). Sponge binding is carried entirely by `sponge_info` in `DomainSeparator::derive`. Spec test vectors regenerated to match.

Also added: `StaticSigmaProtocol` trait for type-level (no-instance) protocol ID access.

---

## Design decisions Michele may probe


| Question                                                     | Answer                                                                                                                                                                                                       |
| ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Why SHA-512 and not SHA-256?                                 | 64-byte output fits the existing `[u8; 64]` protocol slot directly — no second KDF/expansion step needed.                                                                                                    |
| Should `sha2` be in spongefish default features?             | `derive` is the only constructor; it must be available by default. Can be made opt-in if he prefers.                                                                                                         |
| Why does `WithInstance` borrow instead of own?               | Enables `I: ?Sized` (slice/str instances). Lifetime disappears immediately — `to_prover`/`std_prover` absorb the instance into sponge state and return an owned `ProverState`.                               |
| Why is `domsep` a public field?                              | Allows test assertions (`a.domsep == b.domsep`) and external inspection. Construction is still controlled (other fields private). Can be made private with an accessor.                                      |
| `domain_separator!("proto")` with no session — is that safe? | DSFS enforces mandatory session at `prove`/`verify`. Spongefish macro is permissive for simple/test usage; empty session is cryptographically distinct from any real session.                                |
| CO25 §8.2 — instance placement                               | Construction 4.3 hashes session + instance together into the sponge init. Here session is folded into `domsep`, instance is absorbed separately but still before any proof message. Security argument holds. |


