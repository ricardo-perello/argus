# Keys-as-Inputs Preprocessing NARG

**Audience:** Christian / Giacomo / Andrew / Chiesa / Michele — implementation review.

**Status:** Shipped on `feat/keys-as-inputs-pnia` (both `Argus` and `spongefish-dsfs`).
Replaces the path-2 `PreparedArgument` adapters and the key-storing `PreparedDsfsArgument`
wrapper. Plain path, proof bytes, and transcript invariants are unchanged.

**Updated 2026-06-01** (Chiesa / Giacomo feedback round):

- The indexer's single method is `PreprocessingCore::preprocess(ix) -> (pk, vk)`. The
  `ProvingKey { key, committed_index }` wrapper is **gone**.
- The committed-index trait is `CommittedIndex` (was `VerifierKeyCommitment`) and is
  implemented by **both** the prover key and the verifier key. The compiled PNIA derives
  the transcript digest on the fly: `pk.committed_index()` on the prover side,
  `vk.committed_index()` on the verifier side.
- Channel alphabet is an associated type: `trait ProverChannel { type Unit; … }` (was the
  generic `ProverChannel<U = u8>`). Byte-oriented protocols pin it with
  `ProverChannel<Unit = u8>`.

**Design source of truth:** `~/wiki/wiki/projects/argus/prover-verifier-role-separation.md` (v4)
and `~/wiki/2026-06-01.md` (this feedback round).

---

## 1. TL;DR

The compiled preprocessing non-interactive object is **stateless**: it holds the
protocol body and the sponge, nothing else. The indexer (a separate party) runs
`preprocess(ix)` once and returns a prover key and a verifier key; `prove` takes the prover
key, `verify` takes the verifier key. Both keys can produce the committed index
(`CommittedIndex`), so the PNIA binds it without a precomputed wrapper. Plain `IA → NIA`
and preprocessed `PIA → PNIA` are structurally parallel. A value built to verify cannot
prove (no method, no key).

What this fixes:

- **POC-A — verifier can prove.** A prepared wrapper exposed both methods. Gone:
`prove` requires a `ProverKey`, `verify` requires a `VerifierKey`; mixing them is a
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
                                            body.preprocess(ix) ─► (pk, vk)
  nia.prove (session, x, w)                 pnia.prove (&pk, session, x, w)
  nia.verify(session, x, proof)             pnia.verify(&vk, session, x, proof)
```

Both keys implement `CommittedIndex`. The PNIA derives the transcript digest on the fly
from whichever key it is handed: `pk.committed_index()` on the prover side,
`vk.committed_index()` on the verifier side. The author's obligation is that the two agree
(`pk.committed_index() == vk.committed_index()` for keys from the same `preprocess(ix)`); they
typically route through one shared helper, so the bytes can't drift. That obligation is
also **machine-checked**: the backend runs the indexer through
`PreprocessingCore::preprocess_checked`, which calls `preprocess` and `debug_assert`s the two
committed indices match — a buggy indexer fails loudly at preprocessing time in debug/test builds,
not as an opaque verify failure. The prover never holds `vk`, and there is no
precomputed-digest wrapper.

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
└─ PreprocessingCore : ProtocolCore           type Index;
      │                                       type ProverKey:   CommittedIndex
      │                                       type VerifierKey: CommittedIndex
      │   fn preprocess(&self, &Index) -> (ProverKey, VerifierKey)    ◄═══ the INDEXER (3rd party)
      │
      ├─ PreprocessingInteractiveArgument     ◄─ AUTHOR
      │     fn prove (&self, ch, pk, x, w)
      │     fn verify(&self, ch, vk, x) -> Result
      │
      ├─ PreprocessingNonInteractiveArgument  ◄─ DSFS  (keys are INPUTS; object stores none)
      │     type Session
      │     fn prove (&self, &ProverKey,   session, x, w) -> NargProof   (binds pk.committed_index())
      │     fn verify(&self, &VerifierKey, session, x, proof) -> Result  (binds vk.committed_index())
      │
      └─ (reduction variants of the two above)
```

`CommittedIndex` (one method, `committed_index() -> CommittedIndexBytes`) is implemented by
both key types. No `ProvingKey` wrapper: now that the prover key can produce the digest
itself, the indexer's `preprocess(ix)` is the only setup step.

```text
Dsfs<IA>  : InteractiveArgument               ──►  NonInteractiveArgument
Dsfs<IR>  : InteractiveReduction              ──►  NonInteractiveReduction
Dsfs<PIA> : PreprocessingInteractiveArgument  ──►  PreprocessingNonInteractiveArgument
Dsfs<PIR> : PreprocessingInteractiveReduction ──►  PreprocessingNonInteractiveReduction
```

**Optional role wrappers** — concrete structs over the non-interactive plane, *not*
traits. Built bottom-up from `(nia, key)`; never narrow a both-keys object:

```rust
pub struct Prover<'a, N: PreprocessingNonInteractiveArgument>   { nia: &'a N, prover_key: &'a N::ProverKey }
pub struct Verifier<'a, N: PreprocessingNonInteractiveArgument> { nia: &'a N, verifier_key: &'a N::VerifierKey }
```

`Verifier` exposes only `verify`; `Prover` exposes only `prove`. Capability follows key
possession.

---

## 4. Authoring (unchanged)

Same `impl_interactive_argument!` / `impl_preprocessing_argument!` macros, same one-block
syntax. Preprocessing authors use the `preprocess` verb for setup; the channel body stays
unchanged.

```rust
// preprocessed_lookup.rs (unchanged)
ia_core::impl_preprocessing_argument! {
    impl PreprocessingInteractiveArgument for PreprocessedLookup {
        fn protocol_id(&self) -> impl AsRef<[u8]> { … }
        type Instance = (u32, u32);  type Witness = ();
        type Index = Vec<u32>;
        type ProverKey = LookupProverKey;  type VerifierKey = LookupVerifierKey;
        fn preprocess(&self, ix) -> (pk, vk) { … }
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
let (pk, vk) = pnia.preprocess(&table);                   // bare (ProverKey, VerifierKey)
let proof    = pnia.prove (&pk, &session, &(3, table[3]), &());
pnia.verify(&vk, &session, &(3, table[3]), &proof)?;
```

### 5.3 Committed-index flow (keys as inputs, no wrapper)

The indexer ships the **bare** keys; there is no `ProvingKey` wrapper. Each key produces
the committed index on demand via `CommittedIndex`, and the PNIA derives the transcript
digest from whichever key it holds.

Who holds what:


| Party    | Receives from indexer | Reads / re-derives                                                                |
| -------- | --------------------- | --------------------------------------------------------------------------------- |
| Indexer  | `ix`                  | calls `preprocess(ix)`; ships `pk` to the prover and `vk` to the verifier.        |
| Prover   | `ProverKey`           | raw prover material; PNIA binds `pk.committed_index()` into the transcript.        |
| Verifier | `VerifierKey`         | compact key; PNIA binds `vk.committed_index()` into the transcript.               |


The author writes `PreprocessingCore::preprocess` plus a `CommittedIndex` impl on **each** key.
The two impls must return identical bytes for keys from the same `preprocess(ix)` — route them
through one shared helper and they can't drift.

**Example — `PreprocessedLookup`** (Merkle vector-commitment opening;
`crates/argus-examples/src/bin/preprocessed_lookup.rs`). The keys are genuinely asymmetric:
the prover holds `O(n)` of `table + tree`; the verifier holds 36 bytes (`root + n`). Both
recompute the *same* digest from what they hold.

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

        fn preprocess(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
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

// One canonical layout, used by both keys.
fn lookup_committed_index(root: &[u8; 32], n: u32) -> CommittedIndexBytes {
    let mut out = Vec::with_capacity(b"preprocessed-lookup:vk:v1".len() + 32 + 4);
    out.extend_from_slice(b"preprocessed-lookup:vk:v1");
    out.extend_from_slice(root);
    out.extend_from_slice(&n.to_le_bytes());
    CommittedIndexBytes::new(out)
}

impl CommittedIndex for LookupVerifierKey {
    fn committed_index(&self) -> CommittedIndexBytes {
        lookup_committed_index(&self.root, self.n)
    }
}

impl CommittedIndex for LookupProverKey {
    fn committed_index(&self) -> CommittedIndexBytes {
        let root = *self.tree.root().as_bytes();
        let n    = u32::try_from(self.table.len()).expect("table size fits in u32");
        lookup_committed_index(&root, n)   // identical bytes to the verifier key
    }
}
```

What the DSFS `prove` does on top of the author's keys (verify is symmetric on `vk`):

```rust
fn prove(&self, prover_key: &Self::ProverKey, session, x, w) -> NargProof {
    let committed_index = prover_key.committed_index();   // derived from pk, on the fly
    // … absorb committed_index + instance, then run the keyed body …
}
```

**Loading pre-computed keys** (production prover/verifier machines — no indexer rerun;
the keys came from the offline setup):

```rust
// prover machine: has only the prover key (no vk anywhere)
let proof = pnia.prove(&prover_key_from_disk, &session, &instance, &witness);

// verifier machine: has only vk
pnia.verify(&vk_from_disk, &session, &instance, &proof)?;
```

`prover_key.committed_index()` must equal `vk.committed_index()`. Drift causes diverging
transcripts and a verify failure — soundness is preserved, the rollout problem is detected
on the wire.

### 5.4 Optional role wrappers (capability typing)

```rust
use ia_core::{Prover, Verifier};

let prover   = Prover::new(&pnia, &pk);
let verifier = Verifier::new(&pnia, &vk);

let proof = prover.prove(&session, &instance, &witness);
verifier.verify(&session, &instance, &proof)?;
// prover.verify(...)            // ❌ no method
// pnia.prove(&vk, ...)          // ❌ type error: expected &ProverKey, found &VerifierKey
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

The whole API difference: one extra preprocessing step and one key argument.

### 5.6 Two- and three-machine deployment

```text
Preprocessed                                         Plain
┌─ setup machine = INDEXER ─────────────┐            (no indexer)
│ let (pk, vk) = pnia.preprocess(&ix);       │            prover machine          verifier machine
│  ── pk ─► prover                      │            let p = dsfs::… ;        let v = dsfs::… ;
│  ── vk ─► verifier                    │            p.prove(s,x,w) ─proof─►  v.verify(s,x,proof)
└────────────────────────────────────────┘
  prover:    let p = dsfs::…(body, sponge);  p.prove(&pk, s, x, w)  ─proof─► verifier: let v = dsfs::…(body, sponge);  v.verify(&vk, s, x, proof)
```

Each machine independently constructs the same stateless `pnia` from the public body +
sponge. The prover binary never contains `vk`; the verifier binary never contains `pk`
or `prove`. The committed index is the agreement handshake — the prover binds
`pk.committed_index()`, the verifier binds `vk.committed_index()`, and the author's
`CommittedIndex` impls guarantee the two agree. Disagreement ⇒ diverging transcripts ⇒
`verify` fails. This is the same separation `live-channel` already enforces for
interactive runs; the non-interactive types now match it.

---

## 6. What Changed in the Code

### `ia-core` (Argus / `crates/ia-core`)


| change                                                                                                                                                  | location                          | kind          |
| ------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------- | ------------- |
| rename the setup action to `PreprocessingCore::preprocess` and add `preprocess_checked` for key-commitment consistency checks                           | `core.rs`                         | API           |
| bound both `PreprocessingCore::ProverKey` and `PreprocessingCore::VerifierKey` by `CommittedIndex`                                                       | `core.rs`, `preprocessing/`       | API           |
| define `PreprocessingNonInteractiveArgument`/`Reduction` as keys-as-inputs traits: compiled objects are stateless, `prove` takes `&ProverKey`, `verify` takes `&VerifierKey` | `noninteractive/preprocessing.rs` | trait reshape |
| add `Prover`/`Verifier` (+ reduction) convenience wrapper structs over `(narg, key)`                                                                     | `noninteractive/roles.rs`         | additive      |
| keep mixed plain/preprocessing composition explicit through `TrivialIndexedArgument` / `TrivialIndexedReduction`                                         | `interactive/adapters/`           | additive      |
| update exports around `CommittedIndex`, role wrappers, and preprocessing NARG traits                                                                     | `lib.rs`                          | API           |


### `spongefish-dsfs`


| change                                                                                                                                                                                                                                  | location                | kind       |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- | ---------- |
| rename `UnpreparedDsfs{Argument,Reduction}` → `PreprocessedDsfs{Argument,Reduction}` (still the stateless `{ia, sponge}` object)                                                                                                        | `compile.rs`            | rename     |
| implement `PreprocessingNonInteractiveArgument`/`Reduction` for the renamed types: `preprocess` runs `body.preprocess_checked(ix)`; `prove`/`verify` derive committed-index bytes from the passed-in key and delegate to the runners | `compile.rs`            | trait impl |
| remove `.prepare(&ix)` / `.with_keys(pk, vk)` methods                                                                                                                                                                                   | `compile.rs`            | removal    |
| delete the key-storing `PreparedDsfs{Argument,Reduction}` wrappers                                                                                                                                                                      | `prepared.rs` (deleted) | removal    |
| move the four transcript runners **verbatim** into `runners.rs` (now `pub(crate)`)                                                                                                                                                      | `runners.rs` (new)      | move       |
| update `lib.rs` exports + module wiring                                                                                                                                                                                                 | `lib.rs`                | API        |


**Plain path (`DsfsArgument`/`DsfsReduction` + `plain_non_interactive_*`) is unchanged.**

### 6.1 Follow-up (2026-06-01 feedback round)

On top of the keys-as-inputs PR above:

- **`ia-core`**: no `ProvingKey<PK>` wrapper; no setup method on the PNIA traits (only
  `PreprocessingCore::preprocess` remains); bound `PreprocessingCore::ProverKey: CommittedIndex`;
  add the provided `PreprocessingCore::preprocess_checked` (`debug_assert`s `pk`/`vk` committed
  indices match); rename `VerifierKeyCommitment` → `CommittedIndex`; `Prover`/`ProverReduction` hold
  `&N::ProverKey` instead of `&ProvingKey<…>`; `ProverChannel`/`VerifierChannel` take an
  associated `type Unit` instead of the generic `<U = u8>`.
- **`spongefish-dsfs`**: each wrapper's `PreprocessingCore::preprocess` runs the body through
  `preprocess_checked`; `prove` derives `committed_index` from
  `prover_key.committed_index()`; channel impls gain `type Unit = DS::U`.
- **Protocols / examples / WARP**: every `ProverKey` now implements `CommittedIndex`
  (sharing a helper with its `VerifierKey`); byte-oriented `prove`/`verify` pin the
  channel with `ProverChannel<Unit = u8>` / `VerifierChannel<Unit = u8>`.

Proof bytes still byte-identical; the same 3 pre-existing `sigma-bridge` baseline failures.

---

## 7. Migration Reference

*See §5.3 for the keys-as-inputs flow and the shared `committed_index` helper.*


| Before                                                                                    | After                                                                                                       |
| ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `let prepared = dsfs::preprocessing_non_interactive_argument(body, sponge).prepare(&ix);` | `let pnia = dsfs::preprocessing_non_interactive_argument(body, sponge);` `let (pk, vk) = pnia.preprocess(&ix);` |
| `prepared.prove(&session, &x, &w)`                                                        | `pnia.prove(&pk, &session, &x, &w)`                                                                         |
| `prepared.verify(&session, &x, &proof)`                                                   | `pnia.verify(&vk, &session, &x, &proof)`                                                                    |
| `prepared.committed_index()`                                                              | `pk.committed_index()` or `vk.committed_index()`                                                            |
| `prepared.prover_key()`                                                                   | `pk` (the prover key itself)                                                                                |
| `prepared.verifier_key()`                                                                 | `vk` (from `preprocess`)                                                                                    |
| old `pnia.preprocess(&ix)` returning a wrapped proving key                                 | `pnia.preprocess(&ix)` returns bare `(pk, vk)` — no `ProvingKey` wrapper                                    |
| `impl VerifierKeyCommitment for VK`                                                        | `impl CommittedIndex for VK` **and** `impl CommittedIndex for PK` (same bytes)                              |
| `fn prove<P: ProverChannel>` / `fn verify<V: VerifierChannel>`                             | `fn prove<P: ProverChannel<Unit = u8>>` / `fn verify<V: VerifierChannel<Unit = u8>>`                       |


If the body type was `Preprocessed`-bound for a generic helper, switch the helper to take
`pk: &…ProverKey` + `vk: &…VerifierKey` (or `&CommittedIndexBytes`) as explicit args.

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


**Proof bytes are byte-identical to pre-refactor.** The transcript runners and the absorb
path (`IndexedInstanceRef::new(committed_index, instance)` via
`DomainSeparator::derive(...).instance(...)`) are unchanged; the committed index is now
derived from `pk.committed_index()` on the prover side and `vk.committed_index()` on the
verifier side, which return the same bytes. The plain path is untouched, so `sigma-bridge`
golden-vector parity (the cases that already pass) still passes.

**Capability guarantees are compile-time:** `pnia.prove(&vk, …)` is a type error; a
`Verifier` value has no `prove` method.

---

## 9. Decisions and Deviations from the Plan

- **No PNIA-level setup method.** An earlier cut added `preprocess()` on the PNIA traits
to wrap setup + bake the digest into a `ProvingKey`. The 2026-06-01 feedback dropped
both: the prover key implements `CommittedIndex` itself, so `PreprocessingCore::preprocess` is
the only setup step and `prove` takes the bare `&ProverKey`.
- **`CommittedIndex` on both keys.** The committed-index trait is implemented by the prover
key *and* the verifier key; consistency (`pk.committed_index() == vk.committed_index()`) is
the author's obligation, kept honest by routing both through one helper. It is also
machine-checked: `PreprocessingCore::preprocess_checked` (a provided method the DSFS backend
runs setup through) `debug_assert`s the two match, so a mismatch panics at preprocessing time
in debug/test builds instead of failing verification opaquely.
- **Channel alphabet is an associated type.** `trait ProverChannel { type Unit; … }`; a
channel has exactly one alphabet. Byte-oriented protocols pin `Unit = u8` at the bound.
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
