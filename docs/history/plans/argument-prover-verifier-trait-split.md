# Prover/Verifier Trait Split + `into_prover` / `into_verifier` (design record)

**Status:** documentation only — *not* implemented on `main`. This records the
initiative from the 2026-05 thread: split each leaf execution trait into a
prover-only and a verifier-only trait, keep authoring unchanged (the macro emits
both halves), and add `into_prover()` / `into_verifier()` to *downgrade* a full
object into a single-capability handle. The full object keeps both methods; the
narrowing is opt-in.

This supersedes the two earlier drafts (a pure trait split, and a pure
`into_*` capability-drop) — the real initiative is **both at once**: the trait
split is the *mechanism*, `into_*` is the *ergonomic entry point* it enables.

---

## 1. The trait surface

Each leaf execution trait is factored into two capability traits — one holding
`prove`, one holding `verify` — and a full trait that is their conjunction:

```rust
pub trait InteractiveArgumentProver: ArgumentCore {
    fn prove<P: ProverChannel<Unit = u8>>(
        &self,
        ch: &mut P,
        instance: &Self::Instance,
        witness: &Self::Witness,
    );
}

pub trait InteractiveArgumentVerifier: ArgumentCore {
    fn verify<V: VerifierChannel<Unit = u8>>(
        &self,
        ch: &mut V,
        instance: &Self::Instance,
    ) -> VerificationResult<()>;
}

/// Full interactive argument = both capabilities.
pub trait InteractiveArgument:
    InteractiveArgumentProver + InteractiveArgumentVerifier {}

impl<T: InteractiveArgumentProver + InteractiveArgumentVerifier>
    InteractiveArgument for T {}
```

So a full `InteractiveArgument` is exactly the stack the thread described:

```text
InteractiveArgument
   = ProtocolCore                  (via ArgumentCore)
   + ArgumentCore                  (Instance, Witness)
   + InteractiveArgumentProver     (prove)
   + InteractiveArgumentVerifier   (verify)
```

The blanket impl means any type implementing both halves *is* an
`InteractiveArgument` for free — no separate impl, and every existing
`T: InteractiveArgument` bound keeps working unchanged.

The non-interactive plane splits the same way. `Session` is shared by both
halves, so it is hoisted onto a small shared core rather than declared twice:

```rust
pub trait NonInteractiveArgumentCore: ArgumentCore { type Session; }

pub trait NonInteractiveArgumentProver: NonInteractiveArgumentCore {
    fn prove(&self, session: &Self::Session,
             instance: &Self::Instance, witness: &Self::Witness) -> NargProof;
}
pub trait NonInteractiveArgumentVerifier: NonInteractiveArgumentCore {
    fn verify(&self, session: &Self::Session,
              instance: &Self::Instance, proof: &NargProof) -> VerificationResult<()>;
}
pub trait NonInteractiveArgument:
    NonInteractiveArgumentProver + NonInteractiveArgumentVerifier {}
impl<T: NonInteractiveArgumentProver + NonInteractiveArgumentVerifier>
    NonInteractiveArgument for T {}
```

---

## 2. Authoring is unchanged — the macro emits both halves

Protocol authors write the *same* single block as today. The macro is what
changes internally: it expands the one block into the two half-impls, and the
blanket impl supplies the full trait.

```rust
// author writes this — identical to the monolithic version
ia_core::impl_interactive_argument! {
    impl InteractiveArgument for Schnorr<G> {
        fn protocol_id(&self) -> impl AsRef<[u8]> { pad_protocol_id(b"schnorr") }
        type Instance = [G; 2];
        type Witness  = G::ScalarField;
        fn prove <P: ProverChannel<Unit = u8>>(&self, ch, x, w) { … }
        fn verify<V: VerifierChannel<Unit = u8>>(&self, ch, x) -> VerificationResult<()> { … }
    }
}

// macro expands to (sketch):
impl ArgumentCore             for Schnorr<G> { type Instance = …; type Witness = …; }
impl InteractiveArgumentProver   for Schnorr<G> { fn prove (…) { … } }
impl InteractiveArgumentVerifier for Schnorr<G> { fn verify(…) -> … { … } }
// + blanket InteractiveArgument for Schnorr<G>
```

The author receives `schnorr_ia: Schnorr<G>`, a **full** `InteractiveArgument`
(all four traits above).

---

## 3. Compile through DSFS

```rust
let schnorr_nia = dsfs::plain_non_interactive_argument(schnorr_ia, dsfs::Keccak::default());
```

`schnorr_nia` is a **full** `NonInteractiveArgument` — it implements both
`NonInteractiveArgumentProver` and `NonInteractiveArgumentVerifier`, so both
methods are directly available:

```rust
let proof = schnorr_nia.prove (&session, &instance, &witness);   // ✓ full object
schnorr_nia.verify(&session, &instance, &proof)?;                // ✓ full object
```

Narrowing is **optional**: holding the full object, you always have both.

---

## 4. `into_prover()` / `into_verifier()` — downgrade to one capability

When you *want* a single-capability handle (to hand to a party or a function
that should only ever do one side), downgrade:

```rust
let verifier = schnorr_nia.into_verifier();   // downgraded: NonInteractiveArgumentVerifier only
let proof_ok = verifier.verify(&session, &instance, &proof)?;
// verifier.prove(...)   // ❌ no such method — the prover capability was dropped
```

`into_verifier()` downgrades the full object into a value that implements
**only the verifier trait** (`InteractiveArgumentVerifier` on the interactive
plane, `NonInteractiveArgumentVerifier` on the compiled plane). `into_prover()`
is the mirror. Mechanically a thin newtype that re-exports one half and
deliberately does not implement the other:

```rust
pub struct VerifierOnly<N>(N);

impl<N: NonInteractiveArgumentVerifier> NonInteractiveArgumentCore for VerifierOnly<N> {
    type Session = N::Session;
}
impl<N: NonInteractiveArgumentVerifier> NonInteractiveArgumentVerifier for VerifierOnly<N> {
    fn verify(&self, s: &N::Session, x: &N::Instance, p: &NargProof)
        -> VerificationResult<()> { self.0.verify(s, x, p) }
}
// NOTE: no `impl NonInteractiveArgumentProver for VerifierOnly<N>` — that is the downgrade.

impl<N: NonInteractiveArgument> /* full */ N {
    fn into_prover(self)   -> ProverOnly<N>   { ProverOnly(self) }
    fn into_verifier(self) -> VerifierOnly<N> { VerifierOnly(self) }
}
```

(If you want to keep the full object usable afterward, the borrowing
`as_prover(&self) -> ProverOnly<&N>` variant is the natural companion; `into_*`
consumes by convention.)

---

## 5. Why the split is the enabling mechanism

`into_verifier()` can only return "a thing that verifies but cannot prove" if
`verify` lives on a trait *separate from* `prove`. With the monolithic leaf
trait there is nowhere to land such a type — any value carrying `verify` also
carries `prove`. The split is what makes the verifier-only handle a real,
statically-checkable type, so generic code can demand exactly one capability:

```rust
fn run_verifier_side(v: impl NonInteractiveArgumentVerifier, …) { … }
// accepts both the full `schnorr_nia` and a downgraded `VerifierOnly<_>`,
// and statically cannot call prove() on either.
```

The full trait + blanket impl keeps this invisible to authors and to existing
`T: InteractiveArgument` consumers.

---

## 6. Preprocessing and reductions follow the same recipe

- **Preprocessing**: `PreprocessingInteractiveArgument` splits into
  `…ArgumentProver` (takes `&ProverKey`) / `…ArgumentVerifier` (takes
  `&VerifierKey`); the conjunction is the full trait. The downgraded handle also
  carries that party's key — `into_prover()` keeps `pk`, `into_verifier()` keeps
  `vk`. This is exactly the `PreprocessingArgumentProver`/`Verifier` pair from the
  thread. (`preprocess` stays on `PreprocessingCore` — it's the indexer, neither
  prover nor verifier, so it is not part of the split.)
- **Reductions**: same split with the reduction return shapes (prover yields the
  target instance/witness pair, verifier yields the target instance).

---

## 7. Relationship to `main`

`main` keeps the leaf traits **monolithic** (`prove` + `verify` on one trait) and
provides single-capability handles only for the *preprocessing* non-interactive
case, as concrete `Prover`/`Verifier` value-level structs built from
`(nia, key)` — `crates/ia-core/src/noninteractive/roles.rs`. That gives the same
"a verifier value cannot prove" guarantee at the *value* level for preprocessing
only.

This initiative generalizes that to the *type* level and to *all* leaves
(plain + preprocessing, argument + reduction): the verifier-only-ness becomes a
property of the trait surface, and `into_verifier()` is the entry point. The cost
is the one v5 already flagged — composition (`ChainedReduction`,
`ReducedArgument`) must emit prover-half and verifier-half impls rather than one
combined impl (`docs/history/interface/iarg-interface-v5.md` §1).

---

## See also

- `docs/keys-as-inputs-preprocessing-presentation.md` — shipped value-level
  `Prover`/`Verifier` structs for preprocessing (§3 trait tree, §5.4 wrappers).
- `docs/history/interface/iarg-interface-v2.md`, `-v3.md` — original plain
  `Prove<P>`/`Verify<V>` split; `-v5.md` §1 — why it was collapsed.
- `crates/ia-core/src/core.rs` — `ProtocolCore` / `ArgumentCore` /
  `ReductionCore` / `PreprocessingCore` (the cores the split sits on).
</content>
