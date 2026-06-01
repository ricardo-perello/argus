# Keys-as-Inputs Preprocessing NARG

**Audience:** Christian / Giacomo / Andrew / Chiesa / Michele — implementation review.

**Status:** Shipped on `feat/keys-as-inputs-pnia` (both `Argus` and `spongefish-dsfs`).
Replaces the path-2 `PreparedArgument` adapters and the key-storing `PreparedDsfsArgument`
wrapper. Plain path, proof bytes, and transcript invariants are unchanged.

**Design source of truth:** `~/wiki/wiki/projects/argus/prover-verifier-role-separation.md` (v4).

---

## 1. TL;DR

The compiled preprocessing non-interactive object is now **stateless**: it holds the
protocol body and the sponge, nothing else. The indexer (a separate party) runs once and
returns a `ProvingKey { key, committed_index }` and a verifier key; `prove` takes the
proving key, `verify` takes the verifier key. Plain `IA → NIA` and preprocessed `PIA → PNIA`
are now structurally parallel. A value built to verify cannot prove (no method, no key).

What this fixes:

- **POC-A — verifier can prove.** A prepared wrapper exposed both methods. Gone:
`prove` requires a `ProvingKey`, `verify` requires a `VerifierKey`; mixing them is a
type error.
- **POC-B — verifier carries the prover key.** The prepared wrapper stored both `pk`
and `vk`. Gone: the compiled `PNIA` stores no keys; only the role that needs a key
receives it.
- **POC-C — build-then-drop.** `into_prover()` would have constructed both keys and
dropped one. Gone: the indexer is its own step, and keys flow as inputs.

---

## 2. The Two Flows

Side by side. Plain is unchanged; preprocessed is the same shape *plus* an indexer step
and one key argument.

```text
PLAIN  (Schnorr, sumcheck, …)             PREPROCESSED  (DLEQ, WARP, lookup, …)

  IA  ─dsfs─► NIA                           PIA  ─dsfs─► PNIA      (stateless, no keys)
                                                          │
                                            pnia.preprocess(ix) ─► (ProvingKey, vk)
  nia.prove (session, x, w)                 pnia.prove (&proving_key, session, x, w)
  nia.verify(session, x, proof)             pnia.verify(&verifier_key, session, x, proof)
```

The proving key bundles `{ key, committed_index }`. `vk.committed_index()` is computed
once at `preprocess` time and cached inside the proving key — the prover binds it without
ever holding `vk`; the verifier re-derives it from `vk`. Single source of truth: `vk`.
No duplication on `vk`. No author obligation.

---

## 3. The Trait Tree

```text
ProtocolCore                                  fn protocol_id(&self) -> impl AsRef<[u8]>
│
├─ ArgumentCore : ProtocolCore                type Instance;  type Witness
│   │
│   ├─ InteractiveArgument                    ◄─ AUTHOR (channel body)
│   │     fn prove (&self, ch, x, w)
│   │     fn verify(&self, ch, x) -> Result
│   │
│   └─ NonInteractiveArgument                 ◄─ DSFS (compiled, stateless)
│         type Session
│         fn prove (&self, session, x, w) -> NargProof
│         fn verify(&self, session, x, proof) -> Result
│
├─ ReductionCore : ProtocolCore               type {Source,Target}{Instance,Witness}
│   │   (same pair: Interactive / NonInteractive Reduction)
│
└─ PreprocessingCore : ProtocolCore           type Index; type ProverKey;
      │                                       type VerifierKey: VerifierKeyCommitment
      │   fn index(&self, &Index) -> (ProverKey, VerifierKey)    ◄═══ the INDEXER (3rd party)
      │
      ├─ PreprocessingInteractiveArgument     ◄─ AUTHOR
      │     fn prove (&self, ch, pk, x, w)
      │     fn verify(&self, ch, vk, x) -> Result
      │
      ├─ PreprocessingNonInteractiveArgument  ◄─ DSFS  (keys are INPUTS; object stores none)
      │     type Session
      │     fn preprocess(&self, ix) -> (ProvingKey<Self::ProverKey>, Self::VerifierKey)
      │     fn prove (&self, &ProvingKey, session, x, w) -> NargProof
      │     fn verify(&self, &VerifierKey, session, x, proof) -> Result
      │
      └─ (reduction variants of the two above)
```

```text
Dsfs<IA>  : InteractiveArgument               ──►  NonInteractiveArgument
Dsfs<IR>  : InteractiveReduction              ──►  NonInteractiveReduction
Dsfs<PIA> : PreprocessingInteractiveArgument  ──►  PreprocessingNonInteractiveArgument
Dsfs<PIR> : PreprocessingInteractiveReduction ──►  PreprocessingNonInteractiveReduction
```

**Optional role wrappers** — concrete structs over the non-interactive plane, *not*
traits. Built bottom-up from `(nia, key)`; never narr8ow a both-keys object:

```rust
pub struct Prover<'a, N: PreprocessingNonInteractiveArgument>   { nia: &'a N, pk: &'a ProvingKey<N::ProverKey> }
pub struct Verifier<'a, N: PreprocessingNonInteractiveArgument> { nia: &'a N, vk: &'a N::VerifierKey }
```

`Verifier` exposes only `verify`; `Prover` exposes only `prove`. Capability follows key
possession.

---

## 4. Authoring (unchanged)

Same `impl_interactive_argument!` / `impl_preprocessing_argument!` macros, same one-block
syntax. Authors don't see the API reshape — only call sites do.

```rust
// preprocessed_lookup.rs (unchanged)
ia_core::impl_preprocessing_argument! {
    impl PreprocessingInteractiveArgument for PreprocessedLookup {
        fn protocol_id(&self) -> impl AsRef<[u8]> { … }
        type Instance = (u32, u32);  type Witness = ();
        type Index = Vec<u32>;
        type ProverKey = LookupProverKey;  type VerifierKey = LookupVerifierKey;
        fn index(&self, ix) -> (pk, vk) { … }
        fn prove (&self, ch, pk, x, w) { … }
        fn verify(&self, ch, vk, x)    { … }
    }
}
```

---

## 5. Compiled Workflows

### 5.1 Plain

```rust
use spongefish_dsfs as dsfs;

let nia   = dsfs::plain_non_interactive_argument(Schnorr::<G>::default(), dsfs::Keccak::default());
let proof = nia.prove (&session, &instance, &witness);
nia.verify(&session, &instance, &proof)?;
```

### 5.2 Preprocessed (the canonical pattern)

```rust
let pnia     = dsfs::preprocessing_non_interactive_argument(PreprocessedLookup, dsfs::Keccak::default());
let (pk, vk) = pnia.preprocess(&table);              // pk: ProvingKey { key, committed_index }
let proof    = pnia.prove (&pk, &session, &(3, table[3]), &());
pnia.verify(&vk, &session, &(3, table[3]), &proof)?;
```

### 5.3 Proving-key anatomy and committed-index flow

The proving key is a thin `ia-core` bundle:

```rust
pub struct ProvingKey<PK> {
    pub key: PK,                          // the author's PreprocessingCore::ProverKey
    pub committed_index: CommittedIndexBytes,
}
```

Who holds what:


| Party    | Receives from indexer                 | Reads / re-derives                                                                                                |
| -------- | ------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Indexer  | `ix`                                  | calls `index(ix)`; computes `ci = vk.committed_index()`; ships `(pk, ci)` to the prover and `vk` to the verifier. |
| Prover   | `ProvingKey { key, committed_index }` | `pk.key` (raw material) + `pk.committed_index` (transcript-bound digest).                                         |
| Verifier | `VerifierKey`                         | re-derives `committed_index` on demand via `vk.committed_index()` — single source of truth.                       |


The author writes only `**PreprocessingCore::index**` and `**VerifierKeyCommitment**` on the
verifier key. The DSFS layer wraps the indexer's output and bakes the digest into the
proving key once, at `preprocess` time.

**Example — `PreprocessedLookup`** (Merkle vector-commitment opening;
`crates/argus-examples/src/bin/preprocessed_lookup.rs`). The keys are genuinely asymmetric:
the prover holds `O(n)` of `table + tree`; the verifier holds 36 bytes (`root + n`).

```rust
// Asymmetric keys.
struct LookupProverKey   { table: Vec<u32>, tree: MerkleTree }
struct LookupVerifierKey { root: [u8; 32], n: u32 }

ia_core::impl_preprocessing_argument! {
    impl PreprocessingInteractiveArgument for PreprocessedLookup {
        type Index       = Vec<u32>;
        type ProverKey   = LookupProverKey;
        type VerifierKey = LookupVerifierKey;
        // …per-claim Instance/Witness + prove/verify omitted…

        fn index(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
            let tree = MerkleTree::new(ix);
            let root = *tree.root().as_bytes();
            let n    = u32::try_from(ix.len()).expect("table size fits in u32");
            (
                LookupProverKey { table: ix.clone(), tree },
                LookupVerifierKey { root, n },
            )
        }
    }
}

// Author's binding contract: the bytes the transcript absorbs to commit to vk.
impl VerifierKeyCommitment for LookupVerifierKey {
    fn committed_index(&self) -> CommittedIndexBytes {
        let mut out = Vec::with_capacity(b"preprocessed-lookup:vk:v1".len() + 32 + 4);
        out.extend_from_slice(b"preprocessed-lookup:vk:v1");
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&self.n.to_le_bytes());
        CommittedIndexBytes::new(out)
    }
}
```

What the DSFS `preprocess` does on top of the author's `index`:

```rust
fn preprocess(&self, ix: &Self::Index) -> (ProvingKey<Self::ProverKey>, Self::VerifierKey) {
    let (pk, vk)        = self.ia.index(ix);          // author's indexer
    let committed_index = vk.committed_index();       // single source of truth = vk
    (ProvingKey::new(pk, committed_index), vk)
}
```

**Loading pre-computed keys** (production prover/verifier machines — no indexer rerun;
the keys came from the offline setup):

```rust
// prover machine: has only what the indexer shipped (no vk anywhere)
let proving_key = ProvingKey::new(pk_from_disk, ci_from_disk);
let proof       = pnia.prove(&proving_key, &session, &instance, &witness);

// verifier machine: has only vk
pnia.verify(&vk_from_disk, &session, &instance, &proof)?;
```

`ci_from_disk` must equal `vk.committed_index()` on the verifier side. Drift causes
diverging transcripts and a verify failure — soundness is preserved, the rollout problem
is detected on the wire.

### 5.4 Optional role wrappers (capability typing)

```rust
use ia_core::{Prover, Verifier};

let prover   = Prover::new(&pnia, &pk);
let verifier = Verifier::new(&pnia, &vk);

let proof = prover.prove(&session, &instance, &witness);
verifier.verify(&session, &instance, &proof)?;
// prover.verify(...)            // ❌ no method
// pnia.prove(&vk, ...)          // ❌ type error: expected &ProvingKey, found &VerifierKey
```

### 5.5 Worked contrast: Schnorr (plain) vs DLEQ (preprocessed)

```rust
// Schnorr — plain. No keys, no indexer.
let nia = dsfs::plain_non_interactive_argument(Schnorr::<G>::default(), dsfs::Keccak::default());
let proof = nia.prove(&session, &[g, h], &x);
nia.verify(&session, &[g, h], &proof)?;

// DLEQ — preprocessed. (g, h) is the reused fixed pair; (u, v) is per-claim.
let pnia     = dsfs::preprocessing_non_interactive_argument(Dleq::<G>::default(), dsfs::Keccak::default());
let (pk, vk) = pnia.preprocess(&(g, h));
let proof    = pnia.prove (&pk, &session, &(u, v), &x);
pnia.verify(&vk, &session, &(u, v), &proof)?;
```

The whole API difference: one extra `preprocess` step and one key argument.

### 5.6 Two- and three-machine deployment

```text
Preprocessed                                         Plain
┌─ setup machine = INDEXER ─────────────┐            (no indexer)
│ let (pk, vk) = pnia.preprocess(&ix);  │            prover machine          verifier machine
│  ── pk ─► prover                      │            let p = dsfs::… ;        let v = dsfs::… ;
│  ── vk ─► verifier                    │            p.prove(s,x,w) ─proof─►  v.verify(s,x,proof)
└────────────────────────────────────────┘
  prover:    let p = dsfs::…(body, sponge);  p.prove(&pk, s, x, w)  ─proof─► verifier: let v = dsfs::…(body, sponge);  v.verify(&vk, s, x, proof)
```

Each machine independently constructs the same stateless `pnia` from the public body +
sponge. The prover binary never contains `vk`; the verifier binary never contains `pk`
or `prove`. `pk.committed_index` is the agreement handshake — the indexer derives it
from `vk` and ships it with `pk`; the verifier re-derives it. Disagreement ⇒ diverging
transcripts ⇒ `verify` fails. This is the same separation `live-channel` already enforces
for interactive runs; the non-interactive types now match it.

---

## 6. What Changed in the Code

### `ia-core` (Argus / `crates/ia-core`)


| change                                                                                                                                      | location                                                   | kind          |
| ------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- | ------------- |
| add `ProvingKey<PK> { key, committed_index }`                                                                                               | `preprocessing/commitment.rs`                              | additive      |
| remove `Preprocessed` trait (stored-key accessors)                                                                                          | `preprocessing/commitment.rs`                              | removal       |
| reshape `PreprocessingNonInteractiveArgument`/`Reduction` from markers into real traits with `preprocess` + keys-as-inputs `prove`/`verify` | `noninteractive/preprocessing.rs`                          | trait reshape |
| add `Prover`/`Verifier` (+ reduction) wrapper structs                                                                                       | `noninteractive/roles.rs` (new)                            | additive      |
| delete path-2 `PreparedArgument`/`PreparedReduction` adapters                                                                               | `interactive/adapters/preprocessing_to_plain.rs` (deleted) | removal       |
| update `lib.rs` exports (drop `Preprocessed`/`PreparedArgument`, add `ProvingKey`/`Prover`/`Verifier`)                                      | `lib.rs`                                                   | API           |


### `spongefish-dsfs`


| change                                                                                                                                                                                                                                  | location                | kind       |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- | ---------- |
| rename `UnpreparedDsfs{Argument,Reduction}` → `PreprocessedDsfs{Argument,Reduction}` (still the stateless `{ia, sponge}` object)                                                                                                        | `compile.rs`            | rename     |
| implement `PreprocessingNonInteractiveArgument`/`Reduction` for the renamed types: `preprocess` runs `body.index(ix)` + bakes `vk.committed_index()` into the proving key; `prove`/`verify` delegate to the runners with passed-in keys | `compile.rs`            | trait impl |
| remove `.prepare(&ix)` / `.with_keys(pk, vk)` methods                                                                                                                                                                                   | `compile.rs`            | removal    |
| delete the key-storing `PreparedDsfs{Argument,Reduction}` wrappers                                                                                                                                                                      | `prepared.rs` (deleted) | removal    |
| move the four transcript runners **verbatim** into `runners.rs` (now `pub(crate)`)                                                                                                                                                      | `runners.rs` (new)      | move       |
| update `lib.rs` exports + module wiring                                                                                                                                                                                                 | `lib.rs`                | API        |


**Plain path (`DsfsArgument`/`DsfsReduction` + `plain_non_interactive_*`) is unchanged.**

---

## 7. Migration Reference

*See §5.3 for the `ProvingKey<PK>` field layout and the indexer's `committed_index`
derivation.*


| Before                                                                                    | After                                                                                                           |
| ----------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `let prepared = dsfs::preprocessing_non_interactive_argument(body, sponge).prepare(&ix);` | `let pnia = dsfs::preprocessing_non_interactive_argument(body, sponge);` `let (pk, vk) = pnia.preprocess(&ix);` |
| `prepared.prove(&session, &x, &w)`                                                        | `pnia.prove(&pk, &session, &x, &w)`                                                                             |
| `prepared.verify(&session, &x, &proof)`                                                   | `pnia.verify(&vk, &session, &x, &proof)`                                                                        |
| `prepared.committed_index()`                                                              | `pk.committed_index` (field) or `vk.committed_index()`                                                          |
| `prepared.prover_key()`                                                                   | `pk.key` (field)                                                                                                |
| `prepared.verifier_key()`                                                                 | `vk` (from `preprocess`)                                                                                        |
| `PreparedArgument::prepare(body, &ix)` + `.indexed_instance(x)` (path 2)                  | **removed** — call `preprocess(&ix)` and pass keys directly                                                     |
| `Dsfs…with_keys(pk, vk)` for pre-computed keys                                            | **dissolved** — call `prove(&proving_key, …)` / `verify(&vk, …)` directly                                       |


If the body type was `Preprocessed`-bound for a generic helper, switch the helper to take
`pk: &ProvingKey<…>` + `vk: &…VerifierKey` (or `&CommittedIndexBytes`) as explicit args.

---

## 8. Verification


| crate                                   | result                                                                                                                                                                                                  |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ia-core`                               | 22 ✓                                                                                                                                                                                                    |
| `argus-examples` (8 bins + integration) | all ✓                                                                                                                                                                                                   |
| `warp`                                  | 11 ✓                                                                                                                                                                                                    |
| `live-channel`                          | ✓                                                                                                                                                                                                       |
| `sigma-bridge`                          | all ✓ except the documented 3 pre-existing `golden_vectors` plain-path baseline failures (`golden_p256_stdhash`, `golden_bls12381_stdhash`, `golden_bls12381_keccak`) — unrelated, plain path untouched |
| `spongefish-dsfs`                       | 8 ✓                                                                                                                                                                                                     |
| build warnings (both repos)             | 0                                                                                                                                                                                                       |


**Proof bytes are byte-identical to pre-refactor.** The four transcript runners were
moved verbatim into `runners.rs`; the absorb path (`IndexedInstanceRef::new(committed_index, instance)`
via `DomainSeparator::derive(...).instance(...)`) is unchanged; the committed index is
derived identically (`vk.committed_index()`). The plain path is untouched, so
`sigma-bridge` golden-vector parity (the cases that already pass) still passes.

**Capability guarantees are compile-time:** `pnia.prove(&vk, …)` is a type error; a
`Verifier` value has no `prove` method.

---

## 9. Decisions and Deviations from the Plan

- `**preprocess` (not `index`)** is the PNIA-level setup method name — avoids clashing
with `PreprocessingCore::index` (which still returns the bare `(pk, vk)`) and delivers
the team's `prepare → preprocess` rename in one stroke.
- `**IndexedInstance` (owned) stays `pub`** rather than `pub(crate)`: it's harmless and
used by encoding tests; demotion would have introduced unused-import friction. The
borrowed `IndexedInstanceRef` is the one the DSFS runner actually uses.
- `**&self` stays on every method** — `Issue 2` (removing the receiver) is **deferred**
per the 2026-05-29 meeting; this PR changes nothing about it.

---

## 10. Follow-ups (out of scope here)

- **WARP `pk == vk` in v1** — `WarpProverKey` and `WarpVerifierKey` both hold the same
`Arc<WarpStaticMaterial>`. The keys-as-inputs split is in place; the real verifier-memory
win lands once prover-only material (encoded matrix oracles, Merkle trees) moves into
`WarpProverKey`.
- **CY24 §32.7.1 verifier-index commitment** — `WarpVerifierKey::committed_index()` v1
binds `(m, n, k)` only. CY24 prescribes a Merkle commitment to encoded verifier-index
oracles; that's a separate refactor once those oracles live in the verifier key.
- `**Issue 2` — receiver removal / "no runtime `self` state"** — kept deferred. The
docs-level warning (absorb body config via instance / index / `protocol_id`) and the
possible generator/CRS trait remain on the table.

---

## See Also

- `~/wiki/wiki/projects/argus/prover-verifier-role-separation.md` — v4 design doc (the
source of truth this implements).
- `docs/protocol-core-dsfs-presentation.md` — the inheritance-tree presentation this builds on.
- `docs/preprocessing-indexed-relations-v2.md` — the trait surface this refactor reshapes.

