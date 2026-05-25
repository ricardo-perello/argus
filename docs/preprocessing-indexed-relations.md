# Indexed Relations & Preprocessing — Revised Design Proposal

**Status:** Historical draft after Chiesa feedback. Some API names in this
document are intentionally obsolete (`Dsfs::new`, `PreparedDsfs`, blanket
plain-to-indexed conversion). The active implementation plan is
[Preprocessing Indexed Relations v2](preprocessing-indexed-relations-v2.md), and
the current presentation snapshot is
[Protocol Core Tree and DSFS Constructors](protocol-core-dsfs-presentation.md).

## Context

CY24 §32 separates an indexed relation $\mathcal{R}_{\mathbb{i}}$ on triples
$(\mathbb{i}, x, w)$ into:

- $\mathbb{i}$ — the **index**: large, static problem description, such as an
  R1CS matrix tuple or circuit.
- $x$ — the **instance**: small, per-claim public input.
- $w$ — the **witness**: private input.

A deterministic indexer
$\mathcal{I}(\mathbb{i}) \to (\mathsf{pik}, \mathsf{vik})$ splits
preprocessing across prover and verifier. The prover key may be large and
prover-only. The verifier key is public data that fixes the preprocessed
relation before the first public-coin challenge.

The current `ia-core` trait surface is intentionally smaller:
`InteractiveArgument` and `InteractiveReduction` expose only
`Instance` / `Witness` channel programs. That is good UX for ordinary
interactive arguments and should stay that way.

The missing abstraction shows up in WARP. `WARPInstance`
(`crates/warp/src/protocol/ir.rs`) currently bundles `warp.code`,
`warp.config`, `pk`, per-claim instances, and accumulator handles. The verify
path still reconstructs what is effectively a verifier key out of that
prover-side bundle:

```rust
let vk = (instance.pk.1, instance.pk.2, instance.pk.3);
```

This proposal adds preprocessing as a first-class layer without forcing every
non-preprocessing protocol to write `Index = ()` boilerplate.

## Design Requirements

1. **Keep non-preprocessing protocols ergonomic.** Schnorr, sumcheck, sigma-bridge,
   and similar protocols should keep implementing the existing
   `InteractiveArgument` / `InteractiveReduction` traits.
2. **Expose preprocessing protocols explicitly.** Protocols with real preprocessing
   implement `PreprocessingInteractiveArgument` / `PreprocessingInteractiveReduction`.
3. **Use one DSFS compiler wrapper.** Users should not choose between `Dsfs`
   and `IndexedDsfs`. `Dsfs::new(...)` stays the public compiler constructor.
4. **Let composition use heterogeneous preprocessing.** A composed protocol's
   index/key data is a pair of the first component and second component data;
   the two components do not need the same index type.
5. **Absorb the committed verifier index, not necessarily the full key.** DSFS
   binds the preprocessed relation by absorbing `vk.committed_index()` before
   any challenge. For small keys this may be the whole verifier key; for
   holographic or Merkle-backed keys it may be only a digest/root tuple.
6. **Keep transcript mechanics backend-owned.** Protocol code still only calls
   `send_prover_message`, `read_verifier_message`, `read_prover_message`, and
   `send_verifier_message`.
7. **Use `ix` / $\mathbb{i}$ for index notation.** Avoid the previous
   lowercase-l notation for this role.

## Proposed Changes

Steps are in dependency order.

### 1. Keep the existing non-indexed IA/IR traits

`InteractiveArgument` and `InteractiveReduction` remain the user-facing traits
for protocols with no preprocessing:

```rust
pub trait InteractiveArgument {
    type Instance;
    type Witness;

    fn protocol_id(&self) -> impl AsRef<[u8]>;

    fn prove<P: ProverChannel>(
        &self,
        ch: &mut P,
        instance: &Self::Instance,
        witness: &Self::Witness,
    );

    fn verify<V: VerifierChannel>(
        &self,
        ch: &mut V,
        instance: &Self::Instance,
    ) -> VerificationResult<()>;
}
```

No protocol should have to add empty `Index`, `ProverKey`, `VerifierKey`, or
`index()` methods just because a backend can also compile indexed relations.

### 2. Add indexed IA/IR traits

Preprocessing protocols implement a separate surface:

```rust
pub trait PreprocessingInteractiveArgument {
    type Index;
    type ProverKey;
    type VerifierKey: VerifierKeyCommitment;

    type Instance;
    type Witness;

    fn protocol_id(&self) -> impl AsRef<[u8]>;

    /// Deterministic indexer (CY24 §32.1).
    fn index(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey);

    fn prove<P: ProverChannel>(
        &self,
        ch: &mut P,
        pk: &Self::ProverKey,
        instance: &Self::Instance,
        witness: &Self::Witness,
    );

    fn verify<V: VerifierChannel>(
        &self,
        ch: &mut V,
        vk: &Self::VerifierKey,
        instance: &Self::Instance,
    ) -> VerificationResult<()>;
}
```

`PreprocessingInteractiveReduction` mirrors this shape with
`SourceInstance`, `TargetInstance`, `SourceWitness`, and `TargetWitness`.

The conservative Rust rule is: a concrete protocol type implements either the
non-indexed trait or the indexed trait. That makes a blanket lift possible for
ordinary protocols:

```rust
impl<T: InteractiveArgument> PreprocessingInteractiveArgument for T {
    type Index = ();
    type ProverKey = ();
    type VerifierKey = ();

    type Instance = T::Instance;
    type Witness = T::Witness;

    fn protocol_id(&self) -> impl AsRef<[u8]> {
        <T as InteractiveArgument>::protocol_id(self)
    }

    fn index(&self, _: &()) -> ((), ()) {
        ((), ())
    }

    fn prove<P: ProverChannel>(
        &self,
        ch: &mut P,
        _: &(),
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) {
        <T as InteractiveArgument>::prove(self, ch, instance, witness)
    }

    fn verify<V: VerifierChannel>(
        &self,
        ch: &mut V,
        _: &(),
        instance: &Self::Instance,
    ) -> VerificationResult<()> {
        <T as InteractiveArgument>::verify(self, ch, instance)
    }
}
```

The blanket impl is an internal adapter, not boilerplate protocol authors
write by hand. If a protocol has real preprocessing, it implements only the
indexed trait and therefore avoids the overlapping-impl issue. If an existing
protocol type migrates from non-indexed to indexed, remove the old non-indexed
impl or introduce a newtype wrapper.

### 3. Add `VerifierKeyCommitment`

For DSFS, the transcript does not need to absorb the whole verifier key in all
settings. It needs to bind the preprocessed relation before the first challenge.

```rust
pub trait VerifierKeyCommitment {
    /// Canonical public bytes that DSFS absorbs before the first challenge.
    fn committed_index(&self) -> impl AsRef<[u8]> + '_;
}

impl VerifierKeyCommitment for () {
    fn committed_index(&self) -> impl AsRef<[u8]> + '_ {
        &[]
    }
}
```

The protocol author chooses what this returns:

- **Full verifier key** for small, fully-read keys.
- **Digest only** for large keys where the verifier key contains oracle data.
- **Tuple commitment** such as CY24's $(\rho_0, \mathsf{rt}_0)$, where
  $\rho_0$ hashes the raw index and $\mathsf{rt}_0$ commits to the encoded
  verifier oracle.

For composed keys, the default tuple commitment should be length-prefixed and
domain separated, for example:

```text
tag || u64_le(len(c1)) || c1 || u64_le(len(c2)) || c2
```

This avoids ambiguity between `(vk1, vk2)` commitments.

The CY24 COS transformation supports this design: the verifier key is a short
commitment to the long index, and first-round Fiat-Shamir derivation binds that
commitment rather than rereading the full index. The soundness loss is the
offline commitment/collision error, accounted for separately in CY24 §32.8.
Arc App. B uses the same pattern with an index commitment paired with the
verifier-side encoded index handle.

### 4. Use one DSFS wrapper and prepared NARG views

`spongefish-dsfs` should keep a single public compiler wrapper:

```rust
let dsfs = spongefish_dsfs::Dsfs::new(protocol, spongefish_dsfs::Keccak::default());
```

Do **not** add separate indexed NARG traits unless a real generic use case
appears. Otherwise the public vocabulary becomes:

```rust
IA, IR, indexed IA, indexed IR, NIA, NIR, indexed NIA, indexed NIR
```

That is too many names for a small abstraction.

Instead, indexed DSFS produces a **prepared non-interactive view** that stores
the preprocessing keys and implements the existing `NonInteractiveArgument` or
`NonInteractiveReduction` trait:

```rust
let dsfs = spongefish_dsfs::Dsfs::new(protocol, spongefish_dsfs::Keccak::default());
let prepared = dsfs.prepare(&ix);

let proof = prepared.prove(&session, &instance, &witness);
prepared.verify(&session, &instance, &proof)?;
```

Internally:

```rust
pub struct PreparedDsfs<IA, S> {
    dsfs: Dsfs<IA, S>,
    pk: IA::ProverKey,
    vk: IA::VerifierKey,
}

impl<IA, S> NonInteractiveArgument for PreparedDsfs<IA, S>
where
    IA: PreprocessingInteractiveArgument,
{
    // Existing NIA shape: no indexed NARG trait needed.
}
```

The concrete API can expose both:

```rust
let prepared = dsfs.prepare(&ix);        // runs protocol.index(ix)
let prepared = dsfs.with_keys(pk, vk);   // uses externally stored keys
```

For non-preprocessing protocols, `Dsfs<IA, S>` keeps implementing
`NonInteractiveArgument` and `DsfsReduction<IR, S>` keeps implementing
`NonInteractiveReduction` directly. Internally they can still compile through
the indexed adapter with `Index = ()`, `ProverKey = ()`, `VerifierKey = ()`,
and an empty committed index. The unit committed index should be a no-op for
proof bytes; if the implementation gives even the empty commitment its own
transcript marker, that is a layout change and must bump the DSFS-level
`protocol_id`.

DSFS transcript initialization becomes:

```rust
let mut domsep = DomainSeparator::new();
absorb_compiler_domain(&mut domsep, prepared.protocol_id(), session);
absorb_committed_index(&mut domsep, prepared.vk.committed_index()); // NEW
absorb_instance(&mut domsep, instance);
let mut prover = domsep.to_prover(Keccak::default());
prepared.dsfs.protocol.prove(&mut prover, &prepared.pk, instance, witness);
```

The exact helper names are illustrative. The invariant is not: all public data
that fixes the relation, including `vk.committed_index()`, is absorbed before
the first challenge, and protocol code never performs this absorption itself.

Changing the transcript layout, sponge choice, salt policy, or the bytes
returned by `committed_index()` requires a DSFS-level `protocol_id` review and
usually a `protocol_id` bump. The `protocol_id` itself should remain a label for
the compiled proof format; the concrete index is already bound as public input
through `committed_index()`.

### 5. Make security metadata index-aware without disturbing non-preprocessing protocols

Keep the current `ArgumentSecurity` and `ReductionSecurity` traits for
non-preprocessing protocols. Add preprocessing variants:

```rust
pub trait PreprocessingArgumentSecurity: PreprocessingInteractiveArgument {
    type IndexParams;
    type IndexBound;
    type InstanceParams;
    type InstanceBound;

    fn index_security_params(&self, ix: &Self::Index) -> Self::IndexParams;

    fn instance_security_params(
        &self,
        ix_params: &Self::IndexParams,
        instance: &Self::Instance,
    ) -> Self::InstanceParams;

    fn profile_for_instance_params(
        &self,
        ix_params: &Self::IndexParams,
        instance_params: &Self::InstanceParams,
    ) -> SecurityProfile;
}
```

Reduction security gets the analogous source/target shape. Non-indexed
security can be lifted with `IndexParams = ()` and `IndexBound = ()`, but users
do not write that by hand.

WARP's current `WARPSecurityParams` naturally splits into:

- `WARPIndexParams`: code parameters, matrix dimensions, constraint counts,
  OOD sample counts, and shift-query counts derived from the static index.
- `WARPInstanceParams`: per-claim data that can vary between instances under
  the same preprocessed index.

### 6. Compose heterogeneous indices and keys

`ChainedReduction<First, Second>` should not require both reductions to share
the same index or verifier key type. Its indexed impl has paired preprocessing:

```rust
type Index = (First::Index, Second::Index);
type ProverKey = (First::ProverKey, Second::ProverKey);
type VerifierKey = (First::VerifierKey, Second::VerifierKey);

fn index(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
    let (pk1, vk1) = self.first.index(&ix.0);
    let (pk2, vk2) = self.second.index(&ix.1);
    ((pk1, pk2), (vk1, vk2))
}
```

Each reduction step receives only its own key:

```rust
let (x2, w2) = self.first.prove(ch, &pk.0, instance, witness);
self.second.prove(ch, &pk.1, &x2, &w2)
```

`ReducedArgument<Reduction, Argument>` follows the same pattern:

```rust
type Index = (Reduction::Index, Argument::Index);
type ProverKey = (Reduction::ProverKey, Argument::ProverKey);
type VerifierKey = (Reduction::VerifierKey, Argument::VerifierKey);
```

The composed verifier key's `committed_index()` is the canonical commitment to
both component commitments, not an assumption that the two components share an
index.

### 7. Refactor WARP as the first real consumer

WARP should stop storing preprocessing inside the source instance:

```rust
struct WARPIndex<F, P, C, MT> {
    // Static relation data: code, config, Merkle params, constraint system, etc.
}

struct WARPProverKey<F, MT> {
    // Encoded matrices, prover oracle data, Merkle trees, etc.
}

struct WARPVerifierKey<MT> {
    // Matrix commitments/roots and compact verifier metadata.
}

struct WARPInstance<F> {
    // Per-claim public instances and accumulator instances only.
}
```

Then:

```rust
impl PreprocessingInteractiveReduction for WARPReduction<...> {
    type Index = WARPIndex<...>;
    type ProverKey = WARPProverKey<...>;
    type VerifierKey = WARPVerifierKey<...>;
    type SourceInstance = WARPInstance<...>;
    type TargetInstance = DeciderInstance<...>;

    fn index(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
        // Encode A, B, C; build prover oracles; emit verifier commitments.
    }
}
```

The current verifier-side reconstruction:

```rust
let vk = (instance.pk.1, instance.pk.2, instance.pk.3);
```

becomes a direct use of `vk`.

### 8. Unblock `crates/ibcs`

`crates/ibcs` needs a place for the preprocessed verifier oracle commitment.
With the indexed traits in place, iBCS can be written against
`PreprocessingInteractiveArgument` / `PreprocessingInteractiveReduction` from day one
instead of smuggling index material through `Instance`.

## Migration Order

1. Add `VerifierKeyCommitment`, indexed IA/IR traits, and the blanket lift for
   non-indexed IA/IR. Existing protocols should keep compiling unchanged.
2. Add `PreparedDsfs` / `PreparedDsfsReduction` views for preprocessing protocols.
   They store `(pk, vk)` and implement the existing `NonInteractiveArgument` /
   `NonInteractiveReduction` traits. Keep direct NIA/NIR impls for ordinary
   non-preprocessing protocols.
3. Add tuple commitments and heterogeneous preprocessing composition for
   `ChainedReduction` and `ReducedArgument`.
4. Add indexed security traits and blanket lifts from the existing security
   traits.
5. Refactor WARP into `WARPIndex`, `WARPProverKey`, `WARPVerifierKey`, and
   per-claim `WARPInstance`.
6. Implement iBCS on top of the indexed surface.
7. Sweep docs and code comments for index notation: use `ix` in Rust and
   $\mathbb{i}$ in math.

## Transcript Checklist

Any implementation PR for this proposal must explicitly check:

- `vk.committed_index()` is absorbed before the first challenge.
- The instance is absorbed before the first challenge.
- The backend, not protocol code, performs all transcript absorption.
- Prover messages are still absorbed before the challenge for their round.
- Verification consumes exactly the expected proof bytes.
- Any change to committed-index bytes, sponge choice, salt policy, or proof
  layout triggers a DSFS `protocol_id` review.

## Open Questions

1. **Exact `committed_index()` return type.** The design needs canonical public
   bytes for DSFS. The final Rust type can be `impl AsRef<[u8]> + '_`, an
   associated commitment type, or a spongefish codec-backed value. Choose the
   version that fits the codec ownership after the `spongefish-dsfs` split.
2. **Prepared DSFS view shape.** The doc sketches `prepare(&ix)` and
   `with_keys(pk, vk)`. The implementation should decide whether one prepared
   wrapper stores both keys, or whether prover/verifier halves are useful for
   deployment. This should not become new indexed NARG traits unless generic
   code actually needs them.
3. **Implicit instance $y$ (Arnon--Boneh--Fenzi).** This proposal does not
   address ABF's per-instance oracle handle. Land preprocessing first unless
   the iBCS design needs both abstractions at once.
4. **Live-channel runner API.** Live execution should pass `pk`/`vk` to indexed
   protocols but does not absorb transcript bytes. The exact runner function
   names can follow after the DSFS API settles.

## References

- CY24 §32.1 (preprocessing setting), §32.5 (HIOPs), §32.7 (COS
  transformation), §32.8 (offline commitment soundness gap).
- Arc 2024/1731 §5.1, §5.3, App. B Construction B.2.
- Arnon--Boneh--Fenzi 2026/680 §A.1 (IOR formalism with implicit instance
  $y$).
- `docs/adr/0003-instance-aware-security-metadata.md`.
- `docs/security/transcript-invariants.md`.
- `docs/security/domain-separation.md`.
