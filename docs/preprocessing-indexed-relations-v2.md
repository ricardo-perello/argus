# Preprocessing Indexed Relations v2

**Status:** Standalone implementation plan. This file is the source of truth
for adding preprocessing/indexed relations to Argus and the patched
`spongefish-dsfs` backend.

## Goal

Add first-class support for indexed relations without changing the authoring
surface for ordinary protocols.

Plain protocols keep implementing the existing `InteractiveArgument` and
`InteractiveReduction` traits. Preprocessed protocols implement new keyed
indexed traits that expose:

- an indexer `index(ix) -> (pk, vk)`;
- prover execution with `pk`;
- verifier execution with `vk`;
- canonical public bytes `vk.committed_index()` that the backend binds before
  the first challenge.

The DSFS backend remains the only layer that touches sponge/transcript
mechanics. Protocol code, including indexed protocol code, still only uses the
channel API.

## Non-Negotiable Invariants

1. Plain IA/IR authoring remains unchanged.
2. Real preprocessing is keyed execution, not key generation alone.
3. The committed verifier index and instance are absorbed before the first
   challenge.
4. Protocol code never performs transcript absorption or challenge derivation.
5. Existing plain DSFS proof bytes remain unchanged.
6. `with_keys(body, pk, vk)` always derives the committed index from `vk`;
   callers never pass a separate commitment.
7. Prepared interactive adapters reject an `IndexedInstance` whose commitment
   does not match the stored `vk`.

## Core Indexed Vocabulary

Add a new `ia-core::indexed` module and re-export it from `lib.rs`.

### Verifier key commitment

Use an owned, length-prefixed byte wrapper so transcript input is canonical and
does not rely on raw `Vec<u8>` identity encoding.

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedIndexBytes(Vec<u8>);

impl CommittedIndexBytes {
    pub fn new(bytes: Vec<u8>) -> Self;
    pub fn as_bytes(&self) -> &[u8];
}

impl Encoding<[u8]> for CommittedIndexBytes {
    // u64_le(length) || bytes
}

pub trait VerifierKeyCommitment {
    fn committed_index(&self) -> CommittedIndexBytes;
}
```

`()` implements `VerifierKeyCommitment` by returning an empty
`CommittedIndexBytes`.

### Indexed public input

Prepared protocols use a public input pairing the verifier index commitment
with the ordinary per-claim instance.

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedInstance<I> {
    committed_index: CommittedIndexBytes,
    instance: I,
}

impl<I> IndexedInstance<I> {
    pub fn new(committed_index: CommittedIndexBytes, instance: I) -> Self;
    pub fn committed_index(&self) -> &CommittedIndexBytes;
    pub fn inner(&self) -> &I;
    pub fn into_inner(self) -> I;
}

pub struct IndexedInstanceRef<'a, I> {
    committed_index: &'a CommittedIndexBytes,
    instance: &'a I,
}

impl<'a, I> IndexedInstanceRef<'a, I> {
    pub fn new(committed_index: &'a CommittedIndexBytes, instance: &'a I) -> Self;
}
```

Both `IndexedInstance<I>` and `IndexedInstanceRef<'_, I>` implement the same
injective `Encoding<[u8]>` when `I: Encoding<[u8]>`:

```text
tag || committed_index.encode()
    || u64_le(len(instance.encode())) || instance.encode()
```

The tag is fixed, for example `b"argus:indexed-instance:v1"`. The committed
index is not outer-length-prefixed again because `CommittedIndexBytes::encode()`
is already length-delimited.

`IndexedInstanceRef` is required for prepared DSFS ergonomics: it lets the
backend absorb `(committed_index, &x)` while passing the bare `&x` to keyed
protocol execution, without requiring `Clone` on the instance.

### Keyed indexed authoring traits

```rust
pub trait IndexedInteractiveArgument {
    type Index;
    type ProverKey;
    type VerifierKey: VerifierKeyCommitment;
    type Instance;
    type Witness;

    fn protocol_id(&self) -> impl AsRef<[u8]>;
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

pub trait IndexedInteractiveReduction {
    type Index;
    type ProverKey;
    type VerifierKey: VerifierKeyCommitment;
    type SourceInstance;
    type TargetInstance;
    type SourceWitness;
    type TargetWitness;

    fn protocol_id(&self) -> impl AsRef<[u8]>;
    fn index(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey);

    fn prove<P: ProverChannel>(
        &self,
        ch: &mut P,
        pk: &Self::ProverKey,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (Self::TargetInstance, Self::TargetWitness);

    fn verify<V: VerifierChannel>(
        &self,
        ch: &mut V,
        vk: &Self::VerifierKey,
        instance: &Self::SourceInstance,
    ) -> VerificationResult<Self::TargetInstance>;
}
```

There is no blanket implementation from plain IA/IR into these indexed traits.
Plain protocols remain plain. A protocol with real preprocessing implements the
keyed indexed trait directly.

## Prepared Interactive Adapters

Prepared adapters live in `ia-core::indexed`. They make indexed protocols look
like ordinary IA/IR after keys have been generated.

```rust
pub struct PreparedArgument<B: IndexedInteractiveArgument> {
    body: B,
    pk: B::ProverKey,
    vk: B::VerifierKey,
    committed_index: CommittedIndexBytes,
}

pub struct PreparedReduction<B: IndexedInteractiveReduction> {
    body: B,
    pk: B::ProverKey,
    vk: B::VerifierKey,
    committed_index: CommittedIndexBytes,
}
```

All fields are private. The only public constructors are:

```rust
impl<B: IndexedInteractiveArgument> PreparedArgument<B> {
    pub fn prepare(body: B, ix: &B::Index) -> Self;
    pub fn with_keys(body: B, pk: B::ProverKey, vk: B::VerifierKey) -> Self;
    pub fn indexed_instance(&self, instance: B::Instance) -> IndexedInstance<B::Instance>;
}

impl<B: IndexedInteractiveReduction> PreparedReduction<B> {
    pub fn prepare(body: B, ix: &B::Index) -> Self;
    pub fn with_keys(body: B, pk: B::ProverKey, vk: B::VerifierKey) -> Self;
    pub fn indexed_source(
        &self,
        instance: B::SourceInstance,
    ) -> IndexedInstance<B::SourceInstance>;
}
```

`prepare` runs `body.index(ix)`. `with_keys` is for applications that persist
preprocessing keys outside Argus. Both constructors compute:

```rust
let committed_index = vk.committed_index();
```

No constructor accepts a separately supplied commitment.

`PreparedArgument<B>` implements `InteractiveArgument`:

- `Instance = IndexedInstance<B::Instance>`;
- `Witness = B::Witness`;
- `protocol_id()` delegates to `body.protocol_id()`;
- `prove` rejects if `instance.committed_index() != &self.committed_index`,
  then calls `body.prove(ch, &pk, instance.inner(), witness)`;
- `verify` rejects on the same mismatch, then calls
  `body.verify(ch, &vk, instance.inner())`.

`PreparedReduction<B>` implements `InteractiveReduction` analogously, with
`SourceInstance = IndexedInstance<B::SourceInstance>`.

The commitment check belongs in these adapters, not only in DSFS. Prepared
adapters are public IA/IR values, so direct live-channel or test execution must
not be able to bind commitment `C` while verifying with a `vk` whose commitment
is `C'`.

## DSFS API and Backend Changes

The existing plain DSFS API stays unchanged:

```rust
let narg = dsfs::Dsfs::<_, _>::new(schnorr, dsfs::Keccak::default());
let proof = narg.prove(&session, &x, &w);
narg.verify(&session, &x, &proof)?;
```

Add `.prepare(&ix)` and `.with_keys(pk, vk)` as inherent methods on the same
wrappers. An indexed body can be stored in `Dsfs<IA, S, H, SALT_LEN>` even
though the `NonInteractiveArgument` impl is available only after preparation.

```rust
impl<IA, S, H, const SALT_LEN: usize> Dsfs<IA, S, H, SALT_LEN>
where
    IA: IndexedInteractiveArgument,
{
    pub fn prepare(self, ix: &IA::Index) -> PreparedDsfs<IA, S, H, SALT_LEN>;
    pub fn with_keys(
        self,
        pk: IA::ProverKey,
        vk: IA::VerifierKey,
    ) -> PreparedDsfs<IA, S, H, SALT_LEN>;
}

impl<IR, S, H, const SALT_LEN: usize> DsfsReduction<IR, S, H, SALT_LEN>
where
    IR: IndexedInteractiveReduction,
{
    pub fn prepare(self, ix: &IR::Index) -> PreparedDsfsReduction<IR, S, H, SALT_LEN>;
    pub fn with_keys(
        self,
        pk: IR::ProverKey,
        vk: IR::VerifierKey,
    ) -> PreparedDsfsReduction<IR, S, H, SALT_LEN>;
}
```

User-facing prepared DSFS:

```rust
let narg = dsfs::Dsfs::<_, _>::new(indexed_argument, dsfs::Keccak::default())
    .prepare(&ix);
let proof = narg.prove(&session, &x, &w);
narg.verify(&session, &x, &proof)?;
```

For reductions:

```rust
let narg = dsfs::DsfsReduction::<_, _>::new(indexed_reduction, dsfs::Keccak::default())
    .prepare(&ix);
let (proof, target, target_witness) = narg.prove(&session, &x, &w);
let verified_target = narg.verify(&session, &x, &proof)?;
```

`PreparedDsfs` and `PreparedDsfsReduction` accept bare instances. They must not
force callers to construct `IndexedInstance` and must not require `Clone` on the
instance.

Implementation shape in `spongefish-dsfs`:

```rust
pub struct PreparedDsfs<IA, S, H = Keccak, const SALT_LEN: usize = 0> {
    ia: IA,
    pk: IA::ProverKey,
    vk: IA::VerifierKey,
    committed_index: CommittedIndexBytes,
    sponge: H,
    _session: PhantomData<S>,
}
```

`PreparedDsfsReduction` mirrors this for indexed reductions.

Add internal DSFS runners that separate transcript public input from keyed
protocol execution input:

```text
transcript input:
  IndexedInstanceRef { committed_index: &committed_index, instance: &x }

protocol execution input:
  body.prove(ch, &pk, &x, &w)
  body.verify(ch, &vk, &x)
```

This is intentionally not implemented by delegating through
`Dsfs<PreparedArgument<IA>>`, because that public adapter's `Instance` is an
owned `IndexedInstance<IA::Instance>`. Delegating that way would either expose a
clunky API or require `Clone` on instances. The backend may refactor the current
plain helpers in `spongefish-dsfs/src/compile.rs` to share all transcript
setup, salt handling, channel construction, and EOF checking.

The transcript paths are:

```text
plain DSFS:
  DomainSeparator::derive(protocol_id, sponge_info, session).instance(x)

prepared DSFS:
  DomainSeparator::derive(protocol_id, sponge_info, session)
      .instance(IndexedInstanceRef { committed_index, instance: x })
```

No protocol code sees transcript internals. No challenge can be squeezed before
the committed verifier index and instance are absorbed. Existing plain DSFS
proof bytes must remain byte-for-byte unchanged.

## Explicit Trivial-Index Adapters

Mixed plain/indexed composition is supported only through explicit adapters.
There is no blanket conversion.

```rust
pub struct TrivialIndexedArgument<A>(pub A);
pub struct TrivialIndexedReduction<R>(pub R);
```

`TrivialIndexedArgument<A>` implements `IndexedInteractiveArgument` when
`A: InteractiveArgument` with:

```rust
type Index = ();
type ProverKey = ();
type VerifierKey = ();
type Instance = A::Instance;
type Witness = A::Witness;
```

and forwards keyed `prove`/`verify` to the inner plain IA while ignoring the
unit keys. `TrivialIndexedReduction<R>` does the same for plain IRs.

This makes the empty committed index an explicit choice at the composition
site:

```rust
let plain_as_indexed = TrivialIndexedReduction(plain_reduction);
```

## Composition

Implement indexed composition when both components are indexed, either
natively or through explicit trivial-index adapters.

```rust
type Index = (First::Index, Second::Index);
type ProverKey = (First::ProverKey, Second::ProverKey);
type VerifierKey = (First::VerifierKey, Second::VerifierKey);
```

The composed `VerifierKeyCommitment` must be canonical and injective:

```text
tag || u64_le(len(vk1_commit.encode())) || vk1_commit.encode()
    || u64_le(len(vk2_commit.encode())) || vk2_commit.encode()
```

Each composed protocol step receives only its own key:

```rust
let (x2, w2) = first.prove(ch, &pk.0, instance, witness);
second.prove(ch, &pk.1, &x2, &w2);
```

## Security Metadata

Keep existing `ArgumentSecurity` and `ReductionSecurity` unchanged for plain
protocols.

Add indexed variants after the core execution path works:

```rust
pub trait IndexedArgumentSecurity: IndexedInteractiveArgument {
    type IndexParams;
    type IndexBound;
    type InstanceParams;
    type InstanceBound;
    // methods mirror ArgumentSecurity but take index-derived params/bounds
}

pub trait IndexedReductionSecurity: IndexedInteractiveReduction {
    type IndexParams;
    type IndexBound;
    type SourceParams;
    type SourceBound;
    type TargetBound;
    // methods mirror ReductionSecurity but take index-derived params/bounds
}
```

WARP's current security parameters should split into:

- index-derived parameters: code parameters, matrix dimensions, constraint
  counts, OOD sample counts, shift-query counts;
- instance-derived parameters: per-claim public data that varies under a fixed
  preprocessed index.

## Type Lattice

The first implementation does not depend on a public `Protocol<B, P, M, W>`
carrier. Do not block the preprocessing API on it.

After the indexed traits, prepared adapters, and DSFS wrappers are working, add
the sealed lattice as an internal safety layer if it is still useful for generic
compiler code:

```rust
Protocol<B, Plain, Arg, Interactive>
Protocol<PreparedArgument<B>, Preprocessed, Arg, Interactive>
Protocol<B, Plain, Red, Interactive>
Protocol<PreparedReduction<B>, Preprocessed, Red, Interactive>
```

The lattice must have a concrete consumer before it becomes part of the public
API. Candidate consumers are generic compiler dispatch and compile-fail tests
for illegal argument/reduction or interactive/non-interactive operations.

## WARP Migration

WARP is intentionally not a prerequisite for the core preprocessing API.
`crates/warp` is currently excluded from the workspace because of an unrelated
dependency issue. Land the indexed vocabulary and DSFS support first.

When WARP is unblocked, split the current source instance into:

```rust
pub struct WARPIndex<...> {
    // static relation data: code, config, Merkle params, constraint system
}

pub struct WARPProverKey<...> {
    // prover-side encoded matrices, trees, or other heavy preprocessing
}

pub struct WARPVerifierKey<...> {
    // verifier-side dimensions, roots, digest commitments, compact metadata
}

pub struct WARPInstance<...> {
    // per-claim public instances and accumulator instances only
}
```

Then implement `VerifierKeyCommitment` for `WARPVerifierKey` and
`IndexedInteractiveReduction` for `WARPReduction`. The previous pattern of
reading `instance.pk` in the prover and reconstructing `vk` from `instance.pk`
in the verifier must disappear.

## Implementation Phases

1. **Core indexed vocabulary in Argus.**
   Add `ia-core::indexed`, `CommittedIndexBytes`, `VerifierKeyCommitment`,
   `IndexedInstance`, `IndexedInstanceRef`, `IndexedInteractiveArgument`, and
   `IndexedInteractiveReduction`. Add unit tests for injective encodings.

2. **Prepared interactive adapters in Argus.**
   Add `PreparedArgument`, `PreparedReduction`, and explicit trivial-index
   adapters. Test keyed forwarding, `with_keys` commitment derivation, and
   commitment mismatch rejection.

3. **Prepared DSFS wrappers in spongefish.**
   In `../spongefish/spongefish-dsfs`, add `.prepare(&ix)` and
   `.with_keys(pk, vk)` on `Dsfs` and `DsfsReduction` for indexed bodies. Add
   internal indexed DSFS runners using `IndexedInstanceRef`. Refactor existing
   helpers as needed; preserving plain proof bytes is the hard requirement.

4. **Indexed composition in Argus.**
   Add composition impls for indexed reductions and reduced arguments when both
   components are indexed. Add canonical pair commitment tests.

5. **Security metadata in Argus.**
   Add `IndexedArgumentSecurity` and `IndexedReductionSecurity`. Keep the plain
   security traits unchanged.

6. **Optional lattice.**
   Add `ia-core::lattice` only after a concrete consumer exists.

7. **WARP migration after dependency unblocking.**
   Re-enable or separately test `crates/warp`, split WARP's index/key/instance
   types, and migrate it to `IndexedInteractiveReduction`.

## Acceptance Tests

Required during implementation:

- `cargo test -p ia-core`
- `cargo test -p sigma-bridge --test golden_vectors`

Interpretation:

- Existing plain protocol tests must keep passing.
- Plain DSFS proof bytes must remain byte-for-byte unchanged.
- Prepared indexed dummy protocols must prove and verify through DSFS.
- Verification must reject proof bytes with trailing data.
- Direct prepared IA/IR execution must reject an `IndexedInstance` with the
  wrong committed index.
- Prepared DSFS verification must fail when the verifier uses a different
  committed index.
- `with_keys(body, pk, vk)` must derive its cached commitment from `vk`.
- `sigma-bridge` golden-vector failures that predate this work must be recorded
  as baseline before editing DSFS.
- WARP tests are not a core API gate until the dependency issue that excluded
  `crates/warp` from the workspace is fixed.

## Out of Scope

- Hiding/zero-knowledge as a lattice axis.
- Oracle-message protocols and IBCS.
- Holographic verifier-key oracle queries.
- Changing sponge choice, salt policy, or existing plain DSFS transcript layout.
