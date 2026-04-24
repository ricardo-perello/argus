# sigma-bridge (v3)

This note is the **v3** description of `crates/sigma-bridge`: how it turns a `sigma-proofs` [`SigmaProtocol`](https://docs.rs/sigma-proofs) into a non-interactive proof via Argus **IA** channels and **DSFS** spongefish wiring.

For the older, shorter overview see [`sigma-bridge.md`](./sigma-bridge.md).

---

## What the crate does

- Drives a 3-message sigma protocol through `ia-core` (`ProverChannel` / `VerifierChannel`): commitments and responses are sent with `send_prover_message`, challenges with `read_verifier_message` / `send_verifier_message`.
- The returned **proof** is the full spongefish **NARG** byte string: serialized commitment(s), then serialized response(s), in protocol order.
- All Fiat–Shamir sponge operations go through `spongefish::dsfs::SpongeProver` / `SpongeVerifier`; the sigma protocol implementation does not talk to spongefish directly.

---

## Transcript sponge: `StdHash` vs `Keccak`

`spongefish::dsfs` implements `TranscriptSponge`: how a `DomainSeparator` becomes a `ProverState` / `VerifierState`.

| Sponge type | Initialization | Use case |
|-------------|----------------|----------|
| **`spongefish::dsfs::StdHash`** | `DomainSeparator::…::std_prover()` / `std_verifier()` | Same bootstrap as `sigma-proofs::Nizk` on SHAKE128 (spongefish “std” path). |
| **`spongefish::dsfs::Keccak`** | `DomainSeparator::…::to_prover(h)` / `to_verifier(h, …)` | Duplex Keccak (protocol id absorbed as a 64-byte public message, then session and instance). |

`StdHash::prover_state` / `verifier_state` **ignore** the `self` sponge value on purpose: the state is always created with spongefish’s `std_prover` / `std_verifier` semantics so the transcript matches σ-proofs’ non-interactive path when you use the same domain inputs.

Session binding uses `sigma_bridge::derive_session_id`, aligned with `sigma-proofs` [`fiat_shamir`](https://docs.rs/sigma-proofs/latest/sigma_proofs/fiat_shamir/index.html) (SHAKE128 over a fixed domain block, output written to the **high** 32 bytes of a 64-byte field).

---

## `Nizk::prove_batchable` vs the IA channel

`sigma-proofs::Nizk::prove_batchable` does:

1. `DomainSeparator::new(protocol_id).session(…).instance(…).std_prover()`
2. After `prover_commit`, it **`public_message`s** the concatenation of serialized commitments (absorb only for FS).
3. Squeezes the challenge, computes responses, then builds `proof = commitment_bytes || response_bytes` without feeding responses back into the sponge (responses are not part of the FS input for that API).

`sigma-bridge` uses **`send_prover_message`** for each commitment and each response: each call **absorbs** the encoded element and **appends** its `NargSerialize` bytes to the NARG string.

For **Fiat–Shamir**, `public_message` and `prover_message` call the **same** `absorb` on the encoded payload. For types where `NargSerialize` matches the encoding used for absorb (as for `CanonicalLinearRelation` commitments over BLS12-381 etc.), the squeezed challenge matches `Nizk`, and the final NARG equals `Nizk`’s `commitment_bytes || response_bytes`. That is why the **Shake128** golden file can assert byte equality against `prove(spongefish::dsfs::StdHash::default(), …)`.

---

## Protocol id: default vs `ciphersuite`

[`SigmaProtocol::protocol_identifier`](https://docs.rs/sigma-proofs/latest/sigma_proofs/traits/trait.SigmaProtocol.html) for `CanonicalLinearRelation` is curve-specific (e.g. padded `sigma-proofs_Shake128_BLS12381`). That value is what `Nizk` puts in `DomainSeparator::new(…)`.

Some JSON fixtures (notably **`sigma_Keccak1600_BLS12381.json`**) carry a separate **`ciphersuite`** string such as `sigma/OWKeccak1600+Bls12381`. That string is **not** Keccak-based in the transcript: the non-interactive proof still uses the **SHAKE / `std_prover`** stack. The `ciphersuite` field is the **64-byte Fiat–Shamir protocol tag** (padded ASCII) that the **vector generator** used in `DomainSeparator::new`, which can differ from `SigmaProtocol::protocol_identifier`.

API:

- **`prove` / `verify`**: derive the 64-byte tag via `transcript_protocol_id::<P, H>(protocol)` (for `Keccak` + BLS Shake id, the bridge remaps to the OW ciphersuite id to align with that Keccak **sponge** mode in Argus; for `StdHash` the default is the trait’s identifier).
- **`prove_with_protocol_domain` / `verify_with_protocol_domain`**: caller supplies the exact **`[u8; 64]`** tag (e.g. `spongefish::protocol_id(format_args!("{}", json.ciphersuite))`) when reproducing spec JSON that does not use `protocol_identifier()`.

---

## Golden vectors and pinned behavior

| File | What we assert | Notes |
|------|----------------|--------|
| `sigma-proofs_Shake128_BLS12381.json` | **`proof` bytes == `prove(StdHash, …)`** | Matches crates.io `sigma-proofs` + `spongefish` in this workspace. |
| `sigma_Keccak1600_BLS12381.json` | **Ignored** for full byte equality | On `sigma-proofs` **0.2.1** and `spongefish` **0.4.1**, even an **inlined** `Nizk::prove_batchable` with the JSON `ciphersuite` as `protocol_id` does **not** reproduce `proof_batchable` in that file. The testdata appears to come from a **different revision** of the stack. |
| `prove_with_protocol_domain_matches_inlined_nizk_prove_batchable` | **Bridge proof == inlined Nizk** (same inputs) | Guards that `sigma-bridge` stays aligned with σ-proofs’ batchable transcript for the OW `ciphersuite` tag. |

If you need the Keccak-named JSON to pass as golden tests, regenerate `proof_batchable` with the **same** `sigma-proofs` / `spongefish` versions (and generator) as Argus, or pin those crates to the revision that produced the file.

---

## API summary

| Function | Protocol id source |
|----------|-------------------|
| `prove` / `verify` | `transcript_protocol_id::<P, H>(protocol)` |
| `prove_with_protocol_domain` / `verify_with_protocol_domain` | Caller-supplied 64-byte tag (e.g. JSON `ciphersuite`) |

Both take a sponge handle (`spongefish::dsfs::StdHash` or `spongefish::dsfs::Keccak`), `session_id` bytes, the `SigmaProtocol` value, and batchable proof bytes as above.

---

## Minimal example (`StdHash`)

```rust
use sigma_bridge::{prove, verify};
use spongefish::dsfs;

let mut rng = /* impl sigma_proofs::traits::ScalarRng */;
let proof = prove(
    dsfs::StdHash::default(),
    b"session",
    &protocol,
    &witness,
    &mut rng,
)?;
verify(
    dsfs::StdHash::default(),
    b"session",
    &protocol,
    &proof,
)?;
```

---

## Related crates

- `spongefish::dsfs` — `TranscriptSponge`, `SpongeProver`, `SpongeVerifier`
- `crates/ia-core` — `ProverChannel`, `VerifierChannel`
- Tests: `crates/sigma-bridge/tests/golden_vectors.rs`

---

*Document version: **v3**.*
