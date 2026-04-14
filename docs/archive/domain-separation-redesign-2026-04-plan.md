# Domain Separation Redesign (planning notes, April 2026)

> **Archived.** This file is the original design-space write-up. The **implemented** layout is documented in [`domain-separation.md`](../domain-separation.md). Some options here (e.g. SHA-256 with a 32-byte tag) were discussed before the stack settled on **SHA-512 → 64-byte `domsep`** in spongefish and `SpongeInfo` strings in DSFS.

---

**Status (historical):** Updated 2026-04-14 after discussion with Michele.

**Key decisions:** Option B — derivation and session enforcement live in **spongefish**, not DSFS. SHA-256 (32 bytes) replaces the earlier SHA-512 (64 bytes) proposal. DSFS `prove`/`verify` take `&ia` and `session: impl Encoding<[u8]>`. CO25 §8.2 session-placement deviation is accepted as still secure.

**Remaining open items** (preprocessing lift, `Encoding` canonicality, length-prefix abstraction, `dyn`-compatibility): see §5.

---

## 1. Problem Statement

The current domain separation scheme across Argus, sigma-proofs, and spongefish has three interrelated problems.

### 1.1 Static protocol identifiers are insufficient

`InteractiveArgument::protocol_id() -> [u8; 32]` is a static associated function — it has no access to `&self` or runtime state. This works for leaf protocols like Schnorr, where the identifier is determined purely by the generic group type `G`.

It fails for `ComposedRelation` in sigma-proofs. `ComposedRelation<G>` is a runtime enum:

```rust
enum ComposedRelation<G> {
    Simple(CanonicalLinearRelation<G>),
    And(Vec<ComposedRelation<G>>),
    Or(Vec<ComposedRelation<G>>),
    Threshold(u64, Vec<ComposedRelation<G>>),
}
```

Its `protocol_identifier` hashes a tag byte plus the sub-protocol identifiers from the `Vec`. Two values of the same Rust type (`ComposedRelation<BLS12381>`) can have completely different protocol identifiers depending on the composition shape. The identifier is a runtime property, not a type-level constant.

This is not an edge case. Real protocol systems will encounter the same pattern:

- Recursive composition where depth is data-dependent
- Protocol selectors that choose sub-protocols based on instance size
- Multi-party protocols where the composition shape depends on the participant set

**If a composed protocol's identifier is wrong or shared with a structurally different protocol, a prover can re-use a proof from one context in another. This is a domain separation failure.**

### 1.2 The domain separator layering is ad hoc and wasteful

The domain separator absorbed into the sponge before any proof messages must encode three logically independent pieces of information:


| Layer           | What it identifies                          | Who supplies it | When it changes                      |
| --------------- | ------------------------------------------- | --------------- | ------------------------------------ |
| **Protocol**    | The interactive argument being run          | Protocol author | When the protocol changes            |
| **Compilation** | The NARG format: sponge, salt, DSFS version | DSFS backend    | When hash function or layout changes |
| **Session**     | The specific invocation context             | Application     | Every proof                          |


Currently these are combined ad hoc:

- **Argus v5:** `ia_id[32] || sponge_tag[32]` concatenated into 64 bytes. The split point is a convention, not enforced by the encoding.
- **sigma-proofs Nizk:** the full 64-byte `protocol_identifier()` is passed directly to spongefish, with sponge choice baked into the ASCII label (e.g. `"sigma-proofs_Shake128_BLS12381"`).
- **spongefish:** absorbs `protocol[64] || [session[64]] || instance` as raw `public_message` calls with no length framing.

The 32/32 split wastes bytes (zero-padding short labels). The lack of length framing means the encoding is only injective because all three fields happen to be fixed-size. As soon as any field becomes variable-length, the encoding becomes ambiguous.

### 1.3 Session identifiers are optional

In spongefish, `DomainSeparator::session()` is optional:

```rust
// spongefish/src/domain_separator.rs, to_prover()
prover_state.public_message(&self.protocol);
if let Some(session_info) = &self.session {
    prover_state.public_message(session_info);
}
prover_state.public_message(self.instance.0);
```

If session is omitted, the sponge absorbs `protocol || instance` with no delimiter. This creates two problems:

1. **Collision risk:** Without length framing, `(protocol="AB", instance="CD")` absorbs the same bytes as `(protocol="ABCD", instance="")`. The fixed 64-byte sizes currently prevent this, but the safety depends on the size constraint — which is exactly what we want to relax.
2. **Missing binding:** Without a session, a valid proof for statement X under protocol P is valid in *any* context. The application has no way to say "this proof was generated for this specific verification request."

**Session must be mandatory, and this must be enforced at the spongefish layer**, not just at the DSFS layer. Otherwise any direct spongefish consumer (sigma-proofs `Nizk`, future crates) can still skip it.

---

## 2. Proposed Design

### 2.1 `protocol_id` becomes an instance method with variable-length output

```rust
pub trait InteractiveArgument {
    type Instance;
    type Witness;

    /// Protocol identifier. Variable-length, may depend on runtime structure.
    /// For simple protocols: a fixed byte string (e.g. b"schnorr").
    /// For composed protocols: derived from the composition graph.
    fn protocol_id(&self) -> impl AsRef<[u8]>;

    fn prove<P: ProverChannel>(
        &self, ch: &mut P, instance: &Self::Instance, witness: &Self::Witness,
    );
    fn verify<V: VerifierChannel>(
        &self, ch: &mut V, instance: &Self::Instance,
    ) -> VerificationResult<()>;
}
```

Same change for `InteractiveReduction`.

**Consequences for composition types:**

`ChainedReduction` and `ReducedArgument` currently use `PhantomData` because all methods are static:

```rust
// current
pub struct ChainedReduction<First, Second>(PhantomData<(First, Second)>);
```

They must now carry their sub-protocols as values so they can call `self.first.protocol_id()`:

```rust
// proposed
pub struct ChainedReduction<First, Second> {
    pub first: First,
    pub second: Second,
}
```

For zero-sized types (e.g. `ChainedReduction<WARPReduction, WARPDeciderIA>`), the struct is still zero-sized. The compiler optimizes `&self` on ZSTs to nothing.

**Consequences for DSFS entry points:**

```rust
// current
pub fn prove<IA: InteractiveArgument>(session: [u8; 64], instance, witness) -> Vec<u8>

// proposed (decided 2026-04-14)
pub fn prove<IA, S>(
    ia: &IA,
    session: &S,
    instance: &IA::Instance,
    witness: &IA::Witness,
) -> Vec<u8>
where
    IA: InteractiveArgument,
    S: Encoding<[u8]>,
```

Session becomes anything implementing `spongefish::Encoding<[u8]>` rather than a raw `&[u8]`. This lets applications pass structured session data (transaction hashes, ceremony state, nested records) and get a consistent byte representation without hand-serializing. The canonical-encoding guarantees of `Encoding<[u8]>` become load-bearing — see §5.

For ZST protocols: `dsfs::prove(&Schnorr, &session, &instance, &witness)` — trivially lightweight.

### 2.2 Structured 32-byte domain separator via SHA-256

Replace the ad-hoc 32/32 concatenation with a principled length-prefixed derivation:

```
domain_sep = SHA-256(
    LE32(len(protocol_id)) || protocol_id
 || LE32(len(sponge_info)) || sponge_info
 || LE32(len(session))     || session
)
→ [u8; 32]
```

Where:

- `protocol_id` — variable-length bytes from the IA's `protocol_id(&self)` (e.g. `b"schnorr"`, or a hash of a composition tree for `ComposedRelation`)
- `sponge_info` — compilation context identifier, e.g. `b"dsfs/v2/keccak-f1600-r136c64"`. Encodes the sponge choice, the DSFS version/format, and any other compilation-level metadata.
- `session` — mandatory application-level context (a transaction id, a nonce, a ceremony identifier — anything that implements `Encoding<[u8]>`)

The derivation lives inside **spongefish** (see §2.3). Callers reach it via `DomainSeparator::derive(protocol_id, sponge_info, session)`. The internal sponge absorption model does not change; only the size of the domain separator field shrinks from 64 to 32 bytes.

**Why SHA-256:**

- 128-bit collision resistance is sufficient for domain separation at our security level. Confirmed with Michele 2026-04-14: the CO25 bounds do *not* require a 64-byte domain separator, as an earlier reading of the paper had suggested.
- Independent of the sponge choice (clean separation of concerns).
- Universally available, including `no_std` (via the `sha2` crate).
- Halves the on-stack `DomainSeparator` footprint relative to the SHA-512 alternative.

**Why length-prefixed encoding:**

Length-prefixed concatenation is injective: no two distinct `(protocol, sponge, session)` triples produce the same hash input. This is a standard technique (TLS 1.3, HKDF, etc.).

The 12 bytes of overhead (3 × LE32) is negligible. 4-byte lengths support fields up to 4 GB, which is more than sufficient. Even 2-byte lengths would work, but 4 bytes aligns naturally and avoids artificial limits.

**Preprocessing:**

`protocol_id` and `sponge_info` are typically known ahead of time. Spongefish already has internal machinery for this kind of prefix hashing; the DSFS API needs a way to surface it so callers can precompute the `SHA-256(protocol_id || sponge_info)` state once per protocol + sponge pair and only absorb the session per proof. The shape of that API is an open item — see §5.

Conceptually:

```rust
// at setup time (once per protocol + sponge choice)
let prefix_hash_state = Sha256::new()
    .chain_update(&(protocol_id.len() as u32).to_le_bytes())
    .chain_update(protocol_id)
    .chain_update(&(sponge_info.len() as u32).to_le_bytes())
    .chain_update(sponge_info);

// at proof time (per session)
let session_bytes = session.encode();
let domsep = prefix_hash_state.clone()
    .chain_update(&(session_bytes.as_ref().len() as u32).to_le_bytes())
    .chain_update(session_bytes.as_ref())
    .finalize();
```

This gives one SHA-256 compression call online per proof, with the protocol/sponge prefix precomputed.

### 2.3 Derivation and session enforcement live in spongefish

**Decision (Michele, 2026-04-14):** the SHA-256 derivation lives in **spongefish**, not in DSFS. All consumers — DSFS, sigma-proofs `Nizk`, and any future crate on spongefish — go through one path that takes `protocol_id`, `sponge_info`, and `session` as required inputs.

Spongefish exposes a new constructor:

```rust
impl DomainSeparator {
    /// Derives the 32-byte domain separator from its three components
    /// using SHA-256 with length-prefixed concatenation.
    /// Session is required — there is no way to omit it.
    pub fn derive(
        protocol_id: &[u8],
        sponge_info: &[u8],
        session: &[u8],
    ) -> Self { /* ... */ }
}
```

**Why spongefish, not DSFS:**

- **Uniform enforcement.** Every spongefish consumer, including sigma-proofs `Nizk`, gets mandatory session binding for free. If derivation lived in DSFS, `Nizk` would need a parallel scheme.
- **One correct implementation.** Length-prefixed encoding and SHA-256 are cryptographic primitives; centralising them prevents drift between crates.
- **Cleaner dependency graph.** The `sha2` dependency ends up on spongefish (a low-level crypto crate) rather than on DSFS (a compiler).

The current optional builder-style `.session()` API in spongefish is deprecated or removed in the same PR. This is a breaking spongefish API change and is the highest-coordination stage of the implementation — see §4.

Michele flagged that spongefish already has some preprocessing / prefix-hashing machinery internally. The DSFS API should expose this so `protocol_id || sponge_info` can be hashed once and only the session varies per proof. The shape of that lift is an open item — see §5.

### 2.4 DSFS wiring against the spongefish derivation

DSFS no longer owns the derivation — it owns the plumbing. The protocol supplies its `protocol_id`, the sponge type supplies its `SPONGE_INFO`, DSFS encodes the session, and spongefish's `DomainSeparator::derive` does the hashing.

```rust
pub fn prove<IA, S, H>(
    ia: &IA,
    session: &S,
    instance: &IA::Instance,
    witness: &IA::Witness,
) -> Vec<u8>
where
    IA: InteractiveArgument,
    S: Encoding<[u8]>,
    H: SpongeInfo + DuplexSpongeInterface<U = u8>,
{
    let session_bytes = session.encode();
    let domsep = DomainSeparator::derive(
        ia.protocol_id().as_ref(),
        H::SPONGE_INFO,
        session_bytes.as_ref(),
    );

    let mut ch = SpongeProver::new(
        domsep.instance(instance).to_prover(H::default())
    );
    ia.prove(&mut ch, instance, witness);
    ch.narg_string().to_vec()
}
```

Where `SpongeInfo` replaces the current `SpongeTag` trait:

```rust
pub trait SpongeInfo: DuplexSpongeInterface<U = u8> {
    /// Compilation-layer identifier, e.g. b"dsfs/v2/keccak-f1600-r136c64"
    const SPONGE_INFO: &'static [u8];
}
```

**Note on CO25 §8.2 and session placement.** Construction 4.3 of the paper initializes the sponge as $\text{st}'_0 := \text{DS.Start}^h(\text{sid}  \mathbf{x})$, i.e. session and instance are absorbed together in the sponge initialization hash `h`. In the proposed design, `session` enters via the SHA-256 domain separator (which parameterises `DS.Start`), while `instance` is absorbed separately via `.instance(instance_bytes)` as a `public_message` before the first round. Both are bound before the first challenge. **Resolved with Michele 2026-04-14:** the deviation is acceptable; the construction is still secure, and we keep the domain-separator/instance split.

---

## 3. Tradeoffs

### What we gain

- **Correctness:** Session is mandatory (enforced at the spongefish API level), encoding is injective, composed protocols work.
- **Uniform enforcement.** Every spongefish consumer (DSFS, sigma-proofs `Nizk`, future crates) goes through `DomainSeparator::derive` — no way to skip session.
- **Flexibility:** Protocol identifiers can be any length, static or runtime-derived.
- **Clean layering:** Protocol, compilation, and session concerns are explicitly separated.
- **Preprocessable:** Protocol + sponge prefix can be precomputed; only session changes per proof. Spongefish already has internal plumbing for this; DSFS needs to expose it.
- **Interoperability:** sigma-proofs `ComposedRelation` can flow through Argus `SigmaIA` without hacks.
- **Structured sessions:** Because session is `Encoding<[u8]>`, callers can pass typed session data (tx hashes, ceremony state) without hand-serializing.

### What we pay

- **SHA-256 dependency in spongefish.** The `sha2` crate is lightweight and `no_std`, but it adds a dependency to spongefish rather than DSFS.
- **Hash hides structure.** The derived 32 bytes are opaque. For debugging, the pre-hash input must be logged separately. Minor ergonomics cost.
- **Breaking API changes** across three crates. `InteractiveArgument`, `InteractiveReduction`, DSFS entry points, spongefish `DomainSeparator`, and sigma-proofs `SigmaProtocol` all change signatures. The spongefish change is the highest-coordination piece.
- **`prove`/`verify` become `&self` methods.** For ZST protocols this is zero-cost. For composed protocols, the struct must be constructed before calling prove/verify. This is a deliberate tradeoff — the protocol descriptor *should* be a value you construct and pass around.
- **Session placement deviates from CO25 §8.2.** The paper absorbs `sid || x` together in `DS.Start^h`. Here, session enters via the domain separator and instance enters separately via `.instance()`. Confirmed acceptable with Michele 2026-04-14.
- **Canonical encoding of session is now load-bearing.** Since session is `Encoding<[u8]>`, the security argument relies on `Encoding` producing a unique byte string for every semantically distinct value. Whether the current `Encoding` trait guarantees this is an open item — see §5.

---

## 4. Implementation Plan

Stages are ordered by dependency: 1 → 2 → 3. Stage 2 (the spongefish PR) is a prerequisite for Stage 3 (DSFS wiring) because DSFS cannot call `DomainSeparator::derive` until spongefish ships it.

### Stage 1: `protocol_id(&self)` and `&self` methods

**Goal:** Make protocol identifiers runtime-capable. Unblock `ComposedRelation` through `SigmaIA`.

**Crates:** `ia-core`, `dsfs`, `sigma-bridge`, `argus-examples`, `warp`

**Changes:**

- `InteractiveArgument`: `fn protocol_id(&self) -> impl AsRef<[u8]>`, `prove`/`verify` take `&self`
- `InteractiveReduction`: same
- `ChainedReduction`, `ReducedArgument`: store sub-protocols as values instead of `PhantomData`
- DSFS `prove`/`verify`: take `ia: &IA`, session becomes `impl Encoding<[u8]>` (mandatory)
- `SigmaIA<S>` calls `self.0.protocol_identifier()` — `StaticSigmaProtocol` becomes unnecessary
- All example protocols: trivial signature update (`&self` on ZSTs)

**Migration:** Mechanical. Every IA/IR impl adds `&self` to three methods. Composition types gain struct fields. DSFS callers pass `&protocol_struct` and `&session` as the first two arguments.

**Compatibility risk:** Low. No semantic change for existing protocols — only signature changes. Can be shipped ahead of Stage 2.

### Stage 2: Spongefish session API (upstream PR)

**Goal:** Add `DomainSeparator::derive` with mandatory session and SHA-256 length-prefixed derivation.

**Crates:** `spongefish` (external crate at v0.5 — requires a coordinated upstream PR with Michele; resolved 2026-04-14 that this is the path)

**Changes:**

- Add `DomainSeparator::derive(protocol_id: &[u8], sponge_info: &[u8], session: &[u8]) -> Self` implementing the SHA-256 length-prefixed derivation internally.
- Add `sha2` dependency to spongefish.
- Expose preprocessing (prefix hash of `protocol_id || sponge_info`) in a way DSFS can reuse — shape TBD, see §5 open item.
- Deprecate or remove `DomainSeparator::new([u8; 64])` and the optional `.session()` call.
- Internal domain separator field shrinks from 64 to 32 bytes.
- Update sigma-proofs `Nizk` to call `DomainSeparator::derive(...)` — it already carries a `session_id`, so the wiring is mechanical.

**Compatibility risk:** Breaking change to spongefish public API. Highest-coordination-cost stage. All spongefish consumers (Argus DSFS, sigma-proofs `Nizk`) update in lockstep.

### Stage 3: DSFS wiring against the new spongefish API

**Goal:** Replace the ad-hoc 32/32 concatenation with a call to `DomainSeparator::derive`.

**Crates:** `dsfs`, `sigma-bridge`

**Changes:**

- Replace `SpongeTag` with `SpongeInfo` (variable-length info string, e.g. `b"dsfs/v2/keccak-f1600-r136c64"`).
- Remove `build_domain_sep` / `dsfs_protocol_id` functions.
- DSFS `prove`/`verify` encode the session, call `DomainSeparator::derive`, then proceed as before.
- Update `sigma_bridge::prove`/`verify` to use the new derivation.
- **No** `sha2` dependency in DSFS — it lives in spongefish.

**Migration:** Internal to dsfs. External callers see no change beyond Stage 1.

**Compatibility risk:** All existing proofs become invalid (different domain separator). Expected — we're fixing a correctness issue.

---

## 5. Resolved decisions and open items

### Resolved with Michele (2026-04-14)

- **Q1 + Q3 — derivation location and session enforcement.** Option B. The SHA-256 derivation lives in spongefish via `DomainSeparator::derive(protocol_id, sponge_info, session)`. Session is a required parameter; there is no way to skip it. All consumers — DSFS, sigma-proofs `Nizk`, any future crate on spongefish — take this one path.
- **Hash choice.** SHA-256 (32-byte output) is sufficient. The previous assumption that CO25 required a 64-byte domain separator was incorrect.
- **Q2 — `sponge_info` format.** `b"dsfs/v2/keccak-f1600-r136c64"` is accepted. The format encodes compilation framework, derivation scheme version, permutation, and rate/capacity parameters. The rate/capacity parameters matter because the Theorem 6.1 bound depends on the capacity `c` (the $25t^2/|\Sigma|^c$ term) — two configurations with the same permutation but different parameters must have distinct `sponge_info` strings.
- **Q5 — CO25 §8.2 session placement.** The deviation is acceptable. Session enters via the SHA-256 domain separator (feeding `DS.Start`); instance enters separately via `.instance()` as a `public_message` before the first round. Both are bound before the first challenge. We keep the domain-separator/instance split.
- **Session type.** DSFS `prove`/`verify` take `session: impl Encoding<[u8]>`, not `&[u8]`. Applications can pass typed session values and rely on `Encoding` to serialize them.
- **`prove`/`verify` signature change.** `ia: &IA` is now the first argument, `&self` is on all IA/IR methods. `StaticSigmaProtocol` becomes unnecessary.

### Open items

**O1. Preprocessing lift into the DSFS API.** Spongefish already has internal prefix-hashing / preprocessing machinery. DSFS should expose this so `SHA-256(LE32(|proto|) || proto || LE32(|sponge|) || sponge)` can be computed once per protocol + sponge pair and only the session varies per proof. What does the DSFS-facing API look like — a `PreparedProver<IA, H>` type, a builder, a free function? Depends on what shape spongefish's internal plumbing exposes.

**O2. Canonical encoding guarantees of `Encoding`.** The session now enters the SHA-256 domain separator as `session.encode()` bytes. The security of session binding depends on `Encoding` producing a unique byte string for every semantically distinct session value — i.e. injectivity at the byte level. Does the current `Encoding<[u8]>` trait guarantee this, or could two distinct values encode to the same bytes? If the trait does not guarantee canonicality, is the fix to strengthen `Encoding` itself or to introduce a dedicated `SessionEncoding` trait for this use case?

**O3. Length-prefixed encoding as a reusable abstraction.** The `LE32(len) || bytes` pattern shows up in the domain-separator derivation and could plausibly appear elsewhere. Rather than inlining it in spongefish's hasher logic, it could live as a reusable impl or combinator (e.g. a `LengthPrefixed<T>` wrapper implementing `Encoding<[u8]>`). Minor refactor, but worth considering as part of the spongefish PR so the pattern is exposed once, cleanly.

**O4. `dyn`-compatibility of `InteractiveArgument` and `Encoding`.** The proposed `fn protocol_id(&self) -> impl AsRef<[u8]>` uses RPITIT, which prevents trait objects. `spongefish::Encoding::encode(&self) -> impl AsRef<T>` has the same pattern (confirmed with a minimal repro). If a future use case needs `dyn InteractiveArgument` or `dyn Encoding<[u8]>` (heterogeneous protocol lists, message serialization over a boxed trait object), we would need either `Cow<'_, [u8]>` returns or a dedicated dyn-friendly shim. Tracked separately — a reference issue against spongefish documents the `Encoding` case so the constraint is visible upstream.