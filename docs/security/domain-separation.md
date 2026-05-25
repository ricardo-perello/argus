# Domain separation (DSFS + spongefish)

This note describes how Argus binds **protocol identity**, **compilation / transcript format**, and **session** into the Fiat–Shamir transcript after the domain-separation refactor. For earlier planning options and staged rollout discussion, see [`../history/domain-separation/domain-separation-redesign-2026-04-plan.md`](../history/domain-separation/domain-separation-redesign-2026-04-plan.md).

---

## Roles of the three inputs

| Input | Meaning | Typical source |
| ----- | ------- | -------------- |
| **Protocol id** | What protocol body is being run (may be runtime-dependent, e.g. composed σ-protocols). | `ProtocolBody::protocol_id(&self)` as `impl AsRef<[u8]>`. |
| **Sponge / compilation info** | Which NARG layout and sponge bootstrap apply (must change if transcript format or sponge changes). | `spongefish::dsfs::SpongeInfo::SPONGE_INFO` per duplex/`StdHash` choice. |
| **Session** | Per-invocation context (ceremony, request id, etc.). | Any `S: spongefish::Encoding<[u8]>`; DSFS uses `session.encode()`. |

All three are required inputs to transcript initialization; there is no “optional session” in the DSFS path.

---

## spongefish: `DomainSeparator::derive`

The spongefish layer absorbs an injective, length-prefixed encoding of the triple:

`LE32(|protocol_id|) || protocol_id || LE32(|sponge_info|) || sponge_info || LE32(|session|) || session`

into spongefish's standard hash transcript, squeezes **32 bytes**, and embeds them as
**`derived_32 || 0x00 * 32`** in the existing 64-byte protocol tag field. That value
is what feeds:

- **`StdHash`**: `StdHash::from_protocol_id(domsep)`, then the **instance** is absorbed as the next public input before messages.
- **Duplex (e.g. Keccak)**: `domsep` as a `public_message`, then the **instance**, then protocol messages (see DSFS).

The `domain_separator!` macro builds protocol bytes with **`protocol_label`**, supplies a fixed macro default **`DOMAIN_SEPARATOR_MACRO_SPONGE_INFO`** for `sponge_info`, and passes **`session_id` / `session_id_from_str`** session bytes into the same derivation. Callers that need a different compilation tag (e.g. DSFS) call **`DomainSeparator::derive`** explicitly with their **`SpongeInfo`** constant.

**Upstream note:** `arkworks-rs/spongefish` main may ship an alternative API (e.g. type-state session binding in #108). Argus tracks a fork that standardizes on **`derive` + `domsep`** for alignment with DSFS and σ-proofs wiring.

---

## DSFS: `SpongeInfo` and constructors

`spongefish::dsfs` defines:

```text
Keccak::SPONGE_INFO   = b"dsfs/v2/keccak-f1600-r136c64"
StdHash::SPONGE_INFO    = b"dsfs/v2/shake128-r168c32"
```

`non_interactive_argument` / `non_interactive_reduction` construct DSFS wrappers
that compute session bytes during `prove` / `verify`, then:

`DomainSeparator::derive(ia.protocol_id().as_ref(), H::SPONGE_INFO, session_bytes.as_ref()).instance(instance)`

and attach the duplex sponge or `std_prover` / `std_verifier` as documented in [`../history/backends/dsfs-v2.md`](../history/backends/dsfs-v2.md).

Prepared indexed DSFS uses the same derivation, but the public input is:

```text
IndexedInstanceRef { committed_index: vk.committed_index(), instance }
```

This binds the committed verifier index and the per-claim instance before the
first challenge while still passing the bare instance to keyed protocol code.

Transcript adapters (`TranscriptSponge` in `spongefish::dsfs`) use the same derivation for both Keccak and `StdHash` so σ-bridge and DSFS agree when both use **`StdHash`** with the same protocol and session fields.

---

## σ-proofs Nizk

`sigma-proofs` transcript init uses the **same** `sponge_info` byte string as DSFS for **`StdHash`** (see `DSFS_STDHASH_SPONGE_INFO` in `sigma-proofs`), so `Nizk` batchable proofs and `sigma_bridge` can share domain inputs when configured consistently.

---

## CO25 §8.2 vs instance placement

Construction 4.3 initializes the sponge from a hash of session-related material and the instance. Here, **session** (and compilation metadata) are folded into **`domsep`**; the **instance** is absorbed in spongefish immediately after, still **before** the first prover/verifier message of the interactive protocol. This split was reviewed for security; see the archived plan for discussion.

---

## Related docs

- [`../history/backends/dsfs-v2.md`](../history/backends/dsfs-v2.md) — Keccak vs `StdHash`, salt, sponge parameters.
- [`../history/protocols/sigma-bridge-v3.md`](../history/protocols/sigma-bridge-v3.md) — bridge and golden vectors.
- [`../history/interface/iarg-interface-v5.md`](../history/interface/iarg-interface-v5.md) — `protocol_id(&self)` and IA surface.
