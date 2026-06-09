# Prover / Verifier Split + Asymmetric DSFS Compilation

> **Superseded design record.** This document describes the intermediate
> architecture implemented on `feat/prover-verifier-trait-split` on 2026-06-05.
> It is not the current API. The production design adopted on 2026-06-08 removes
> conjunction traits, role views, `CombinedIA`, and `CombinedNarg`, and authors
> prover, verifier, and indexer roles natively. See
> [Protocol Shapes](../../architecture/ia-ir.md) and the
> [Role-First Architecture Record](../../architecture/role-first-protocol-architecture-plan.md).

**Historical status:** superseded by the role-first architecture.

**Decided:** 2026-06-05 meeting (Chiesa, Giacomo, Christian).

---

## TL;DR

We split every leaf execution trait into a **prover half** and a **verifier half**, and taught the
DSFS compiler to build *just a prover* (or *just a verifier*) from a protocol body. Two
independently-compiled halves can be glued back into a full non-interactive argument.

- **Authoring is unchanged** — you still write one `impl` block; the macro emits both halves.
- **The transcript is unchanged** — proof bytes are identical; the sigma-proofs `Shake128` golden
  vectors still pass byte-for-byte. This is a pure type-level refactor.
- **New ergonomics:** a full body can be wrapped as `body.into_prover()` or `body.into_verifier()`
  before DSFS compilation. This is a role-view convenience, not a replacement for true asymmetric
  authoring.
- **New capability:** `dsfs(ia_prover) → non-interactive prover`. This is the structural prerequisite
  for recursion / accumulation (a prover that embeds an *inner verifier* without the inner prover).

---

## 1. The problem the split solves

Today a protocol's `prove` and `verify` live on **one** trait:

```rust
trait InteractiveArgument: ArgumentCore {
    fn prove<P: ProverChannel>(&self, ch, x, w);
    fn verify<V: VerifierChannel>(&self, ch, x) -> VerificationResult<()>;
}
```

Any value that can `verify` can also `prove`. There is **nowhere to land** a type that proves but
cannot verify, or vice-versa. That blocks two things we want:

1. **Building one role.** "Hand a party a *prover* and nothing else" can only be a convention, not a
   type.
2. **Recursion.** An accumulation/IVC prover must run the *inner verifier's* algorithm inside its
   circuit — without ever needing the inner prover. With a monolithic trait, depending on the inner
   verifier drags in the inner prover.

## 2. The trait surface (the mechanism)

Each leaf trait is factored into two capability traits and a **marker conjunction**:

```rust
pub trait InteractiveArgumentProver: ArgumentCore {
    fn prove<P: ProverChannel<Unit = u8>>(&self, ch: &mut P, x: &Self::Instance, w: &Self::Witness);
}
pub trait InteractiveArgumentVerifier: ArgumentCore {
    fn verify<V: VerifierChannel<Unit = u8>>(&self, ch: &mut V, x: &Self::Instance)
        -> VerificationResult<()>;
}

/// Full argument = both halves. Pure marker; carries no methods of its own.
pub trait InteractiveArgument: InteractiveArgumentProver + InteractiveArgumentVerifier {}
impl<T: InteractiveArgumentProver + InteractiveArgumentVerifier> InteractiveArgument for T {}
```

The blanket impl means any type implementing both halves **is** an `InteractiveArgument` for free —
every existing `T: InteractiveArgument` bound keeps working unchanged.

Applied to all **8** leaf traits:

| plane            | argument                                   | reduction                                   |
|------------------|--------------------------------------------|---------------------------------------------|
| interactive      | `InteractiveArgument{Prover,Verifier}`     | `InteractiveReduction{Prover,Verifier}`     |
| interactive + pp | `PreprocessingInteractiveArgument{P,V}`    | `PreprocessingInteractiveReduction{P,V}`    |
| non-interactive  | `NonInteractiveArgument{Prover,Verifier}`  | `NonInteractiveReduction{Prover,Verifier}`  |
| non-int. + pp    | `PreprocessingNonInteractiveArgument{P,V}` | `PreprocessingNonInteractiveReduction{P,V}` |

(`preprocess` stays on `PreprocessingCore` — it is the indexer, neither prover nor verifier.)

## 3. Authoring is unchanged — the macro emits both halves

The author writes the **same** block as before:

```rust
ia_core::impl_interactive_argument! {
    impl InteractiveArgument for Schnorr<G> {
        fn protocol_id(&self) -> impl AsRef<[u8]> { pad_protocol_id(b"schnorr") }
        type Instance = [G; 2];
        type Witness  = G::ScalarField;
        fn prove <P: ProverChannel<Unit = u8>>(&self, ch, x, w)        { /* … */ }
        fn verify<V: VerifierChannel<Unit = u8>>(&self, ch, x) -> _    { /* … */ }
    }
}
```

Internally the macro now splits the method block at `fn verify` and emits **two** impls
(`InteractiveArgumentProver` with `prove`, `InteractiveArgumentVerifier` with `verify`) plus the
core impls. The split is done by a small tt-muncher (`__ia_core_emit_prover_verifier!`) and is
robust to attributes / channel-type-parameter naming.

## 4. The pipelines — one compiler, capability induced by the input

The crucial thing: **there is only one DSFS compiler.** `plain_non_interactive_argument(body,
sponge)` has *no trait bound on the body* — it just wraps it. What the compiled object *can do* is
**induced** by which halves the body implements. The same call produces a prover, a verifier, or a
full object depending on what you hand it.

So a "pipeline" is really two independent stages: **(A)** how a body acquires its capabilities,
and **(B)** what you do with the compiled NARG. Here is every combination for an interactive
**argument** (reductions are the exact mirror):

```text
  STAGE A — interactive argument body                    ── one DSFS compile ──▶   compiled NARG can…

  full body (prove + verify) ──────────────────────────────────── dsfs ──▶   .prove()  +  .verify()

  full_body.into_prover()    = ProverOnly<full> ───────────────── dsfs ──▶   .prove()      ← API
  full_body.into_verifier()  = VerifierOnly<full> ─────────────── dsfs ──▶   .verify()       boundary
        (the opposite algorithm is still compiled in — hidden, not absent)

  native prover-only body ─────────────────────────────────────── dsfs ──▶   .prove()      ← dependency
  native verifier-only body ───────────────────────────────────── dsfs ──▶   .verify()       boundary
        (the opposite algorithm does not exist for this type — recursion needs this)

  CombinedIA::new(prover-only body, verifier-only body) ───────── dsfs ──▶   .prove()  +  .verify()
        (glue two one-sided BODIES into a full one, then compile)

  STAGE B — transform compiled NARGs
  CombinedNarg::new(prover NARG, verifier NARG) ──────────────────────────▶   .prove()  +  .verify()
        (glue two one-sided NARGs into a full one, after compile)
```

Two reads of this picture:

- **`into_prover` (role view) vs native one-sided body** produce the *same capability shape* but
  differ in dependency footprint — hidden-but-present vs genuinely-absent. Only the latter expresses
  recursion (an outer prover depending on an inner *verifier* without the inner prover).
- **`CombinedIA` and `CombinedNarg` are the same idea at two altitudes** — combine a prover and a
  verifier into a full object, before vs after compilation.

For **preprocessing** protocols there is no separate key-binding step: the key is passed explicitly,
`nia.prove(&pk, &session, …)` / `nia.verify(&vk, &session, …)`. (The old stateful `Prover`/`Verifier`
key-views were removed — the split already gives the capability separation, and key possession is
just the argument you do or don't hold.)

Concretely, the DSFS wrapper implements the two halves **separately**, with bounds relaxed to
the matching interactive half — this is what makes the capability follow the input:

```rust
// prove path needs only the prover half:
impl<IA, …> NonInteractiveArgumentProver for DsfsArgument<IA, …>
where IA: InteractiveArgumentProver, … { fn prove(…) -> NargProof { … } }

// verify path needs only the verifier half:
impl<IA, …> NonInteractiveArgumentVerifier for DsfsArgument<IA, …>
where IA: InteractiveArgumentVerifier, … { fn verify(…) -> VerificationResult<()> { … } }
```

So a body that implements **only** `InteractiveArgumentProver` compiles to a prover-only object —
the verifier-half impl simply does not resolve. The full-compile path is preserved because the
blanket conjunction re-derives `NonInteractiveArgument` whenever both halves are present.

### 4.1 Role views from a full body

`into_prover()` / `into_verifier()` are ergonomic wrappers over a full protocol body:

```rust
use ia_core::prelude::*;

let prover_body = Schnorr::<G>::default().into_prover();
let verifier_body = Schnorr::<G>::default().into_verifier();

let prover = dsfs::plain_non_interactive_argument(prover_body, Keccak::default());
let verifier = dsfs::plain_non_interactive_argument(verifier_body, Keccak::default());

let proof = prover.prove(&session, &instance, &witness);
verifier.verify(&session, &instance, &proof)?;
```

The wrappers are `ProverOnly<T>` and `VerifierOnly<T>`. They forward `protocol_id` and all core
shape metadata, but implement only the selected executable half. They are useful when a caller has
one full body and wants to hand one party a prover-shaped object and another party a verifier-shaped
object.

Important: role views are an **API boundary**, not a **dependency boundary**. `VerifierOnly<Schnorr>`
still contains a `Schnorr` value whose type implements both halves. This is fine for examples,
deployment wiring, and "do not expose `.prove()` here" APIs. It is not enough for recursion when an
outer prover must depend on the inner verifier algorithm without depending on the inner prover
algorithm.

For preprocessing protocols, `ProverOnly<T>` / `VerifierOnly<T>` also forward `PreprocessingCore` so
DSFS can compile them. The key-possession boundary is then simply *which key each party holds* and
passes in — `nia.prove(&pk, …)` for the prover, `nia.verify(&vk, …)` for the verifier. There is no
separate key-binding wrapper.

### 4.2 True asymmetric bodies

True asymmetric compilation starts from bodies that implement only the half they need:

```rust
let prover  = dsfs::plain_non_interactive_argument(prover_only_body,  Keccak::default());
let proof   = prover.prove(&session, &instance, &witness);   // ✓  prover.verify — does not exist

let verifier = dsfs::plain_non_interactive_argument(verifier_only_body, Keccak::default());
verifier.verify(&session, &instance, &proof)?;               // ✓  verifier.prove — does not exist
```

This is the recursion-relevant capability: a verifier-only body can exist without the prover half in
the type at all. The canonical in-repo smoke test is
`crates/argus-examples/tests/asymmetric_compile.rs`, where `ProverOnlyEcho` implements only
`InteractiveArgumentProver` and `VerifierOnlyEcho` implements only `InteractiveArgumentVerifier`.

### 4.3 Rule of thumb

| Need | Use | What it guarantees |
|------|-----|--------------------|
| Cleaner examples, party wiring, or hiding the opposite method from a call site | `full_body.into_prover()` / `full_body.into_verifier()` | The wrapper exposes only one executable half (other algorithm still present). |
| A verifier dependency that must not include the prover algorithm (recursion) | A native `InteractiveArgumentVerifier` / `InteractiveReductionVerifier` body | The type itself has no prover half. |
| Separate preprocessed parties with key-possession boundaries | A prover-only / verifier-only compiled object; pass `pk` / `vk` explicitly | The prover holds only `pk`; the verifier only `vk`. |
| Gluing a prover-only and verifier-only **body** before compilation | `CombinedIA::new(prover, verifier)` | Type-level shape agreement + `protocol_id` debug guard; result is a full IA body. |
| Recombining independently compiled non-interactive **halves** | `CombinedNarg::new(prover, verifier)` | Same shape agreement + guard, one altitude up (compiled NARGs). |

## 5. Recombination — `CombinedIA` (bodies) and `CombinedNarg` (NARGs)

The inverse of building one role is gluing two back together. It exists at both altitudes:

```rust
// before compilation — combine two one-sided BODIES into a full interactive body:
let full_body = CombinedIA::new(prover_only_body, verifier_only_body);  // : InteractiveArgument
let nia = dsfs::plain_non_interactive_argument(full_body, Keccak::default());

// after compilation — combine two one-sided NARGs into a full one:
let nia = CombinedNarg::new(prover_narg, verifier_narg);                // : NonInteractiveArgument
let proof = nia.prove(&session, &instance, &witness);
nia.verify(&session, &instance, &proof)?;
```

In both cases the two halves must describe the *same* protocol. Instance / witness (/ session)
agreement is enforced **at the type level**; `protocol_id` agreement is checked at construction
(`debug_assert`). The common case — two halves of one body/spec — satisfies the guard automatically;
it exists to catch two independently-built, *mismatched* halves (which would otherwise fail at verify
with no signal). This is the one soundness-relevant spot in the change.

## 6. Ergonomics — nothing got harder

Calling `.prove()` / `.verify()` now needs the relevant *half-trait* in scope (the conjunction is a
method-less marker). To keep this invisible we added a prelude:

```rust
use ia_core::prelude::*;   // brings every leaf trait — conjunctions + both halves
let proof = schnorr_nia.prove(&session, &instance, &witness);  // just works

let prover = Schnorr::<G>::default().into_prover();    // role view also in prelude
let verifier = Schnorr::<G>::default().into_verifier();
```

Because the conjunctions carry no methods, importing them next to the halves can never create
method-resolution ambiguity. `into_prover()` and `into_verifier()` are extension-trait methods from
the same prelude.

## 7. Safety — this is a *type-level* refactor

No `prove`/`verify` body changed; no absorb/squeeze ordering moved (DSFS Construction 4.3 untouched).
The proof guarantee:

- **sigma-proofs `Shake128` golden vectors pass byte-for-byte** (`sigma-bridge` tests). A prover-only
  compile produces a proof **byte-identical** to the full compile (asserted in the new tests).
- **Role-view compiles are byte-identical** to full compiles when the wrapped full body is the same.
  The wrappers only change Rust method availability, not transcript operations.
- Whole Argus workspace + spongefish-dsfs tests green; zero warnings.

## 8. Design decisions worth a sentence

- **`Session` hoisted to one shared `NonInteractiveSession` trait.** The non-interactive halves each
  need the session type; rather than declare it twice (or per family), one shared supertrait keeps
  `N::Session` unambiguous everywhere with zero consumer churn.
- **Both role views and true asymmetric bodies exist.** `into_prover()` / `into_verifier()` are kept
  because the examples and deployment wiring read better with them. They are deliberately documented
  as wrappers over full bodies, while true asymmetric bodies remain the recursion/dependency story.
- **Removed the stateful `Prover<>` / `Verifier<>` key-views.** They bundled a compiled preprocessing
  NIA with one party's key and exposed one method. After the split, the capability separation comes
  from the prover-only / verifier-only compiled object; key possession is just *which key you pass*.
  So the key is threaded explicitly (`nia.prove(&pk, …)` / `nia.verify(&vk, …)`) and the wrapper layer
  is gone — one fewer concept for the same guarantee.
- **Added `CombinedIA` (body-level) to mirror `CombinedNarg` (NARG-level).** You can now glue a
  prover-only and a verifier-only *body* into a full one before compiling, not only two compiled
  NARGs after — the combine operation exists symmetrically at both altitudes (§5).
- **Composition cost, paid on purpose.** Each combinator (`ChainedReduction`, `ReducedArgument`) now
  needs a prover-half and a verifier-half impl instead of one combined impl. This is the boilerplate
  v5 once removed for lack of a consumer — it now has one (§4), so it is back, deliberately.

## 9. What this unlocks (downstream)

The payoff is **not** on the IA layer — there it is mostly mechanical. It is the structural enabler
for the layers above:

- **Recursion / accumulation / IVC:** an outer prover can now depend on an inner `…Verifier`
  *without* the inner prover — i.e. embed the inner verifier's algorithm in its circuit. This is
  inexpressible with a monolithic leaf trait.
- **iBCS / IOP / VC interfaces (Christian):** the single-role bounds (`run_verifier_side(v: impl
  NonInteractiveArgumentVerifier)`) are now real, statically-checkable types. This is where the
  co-design continues.

## 10. Status & before-merge (cross-repo)

Implemented across **two** repos on branch `feat/prover-verifier-trait-split`:

- **Argus** — `ia-core` trait split + macro + all in-repo consumers (composition, adapters,
  `sigma-bridge`, `warp`, examples) + role-view adapters + new `asymmetric_compile` test.
- **spongefish** — `spongefish-dsfs` half-impls + relaxed runner bounds + `CombinedNarg`.

To merge: push the spongefish branch, push the split `ia-core` to the argus branch spongefish pins,
revert the two temporary local-path `[patch]` entries (one per repo), refresh `Cargo.lock`.

---

## Appendix — change map

| area | files |
|------|-------|
| interactive traits | `ia-core/src/interactive/{argument,reduction,preprocessing}.rs` |
| authoring macro | `ia-core/src/interactive/macros.rs` (`__ia_core_emit_prover_verifier!`) |
| non-interactive traits | `ia-core/src/noninteractive/{argument,reduction,preprocessing,session}.rs` (stateful `roles.rs` key-views **removed**) |
| role views / combine | `ia-core/src/interactive/adapters/{role_views,combined_ia}.rs` (`ProverOnly`/`VerifierOnly`/`into_prover`/`into_verifier`, `CombinedIA`) |
| composition / adapters | `ia-core/src/interactive/composition/{plain,preprocessing}.rs`, `adapters/plain_to_preprocessing.rs`, `noninteractive/adapters/narg_to_interactive.rs` |
| prelude + exports | `ia-core/src/lib.rs` (`pub mod prelude`) |
| DSFS compile + recombine | `spongefish-dsfs/src/{compile.rs, runners.rs, lib.rs}` (`CombinedNarg`) |
| consumers | `sigma-bridge/src/ia.rs`, `warp/src/protocol/ir.rs`, `argus-examples/**` |
| new tests | `argus-examples/tests/asymmetric_compile.rs` |

## See also

- `docs/history/plans/argument-prover-verifier-trait-split.md` — original design record for the
  role-view variant. The final design includes role views as ergonomics, but does not use them as a
  substitute for direct asymmetric bodies.
- `docs/history/interface/iarg-interface-v5.md` §1 — why the composition boilerplate was once removed.
