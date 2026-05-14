# Indexed Relations & Preprocessing — Design Proposal

**Status:** Draft, for advisor review (Chiesa, Orrù).

## Context

CY24 §32 separates an indexed relation $\mathcal{R}_i$ on triples $(\ell, x, w)$ into:

- $\ell$ — the **index**: large, static problem description (e.g. R1CS matrices, a circuit).
- $x$ — the **instance**: small, per-claim public input.
- $w$ — the **witness**: private input.

A deterministic indexer $\mathcal{I}(\ell) \to (\mathsf{pik}, \mathsf{vik})$ splits preprocessing across prover and verifier so that V's online cost is $\mathrm{poly}(|\mathsf{vik}|, |x|)$, independent of $|\ell|$.

The current `ia-core` trait surface collapses $(\ell, x, w)$ into a single `Instance` / `Witness` pair. WARP carries the structure manually: `WARPInstance` (`crates/warp/src/protocol/ir.rs`) bundles `warp.code`, `warp.config`, `pk`, the per-claim instances, and accumulator handles. The verify path at `crates/warp/src/protocol/ir.rs:121` is the smoking gun:

```rust
let vk = (instance.pk.1, instance.pk.2, instance.pk.3);
```

V is already destructuring a prover-only blob to recover what is effectively a $\mathsf{vik}$. This proposal makes the $(\ell, \mathsf{pik}, \mathsf{vik}, x, w)$ split first-class on the IA/IR traits, threads it through composition and the security profile, and binds $\mathsf{vk}$ into the transcript as a public input.

## Proposed changes

Steps are in dependency order. Each is a small, locally-reviewable change.

### 1. Add `Index` / `ProverKey` / `VerifierKey` to the IA and IR traits

`crates/ia-core/src/{argument.rs,reduction.rs}`:

```rust
pub trait InteractiveArgument {
    type Index;          // ℓ
    type ProverKey;      // pik
    type VerifierKey;    // vik

    type Instance;       // x
    type Witness;        // w

    fn protocol_id(&self) -> impl AsRef<[u8]>;

    /// Deterministic indexer (CY24 §32.1).
    fn index(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey);

    fn prove<P: ProverChannel>(
        &self, ch: &mut P,
        pk: &Self::ProverKey,
        instance: &Self::Instance,
        witness: &Self::Witness,
    );

    fn verify<V: VerifierChannel>(
        &self, ch: &mut V,
        vk: &Self::VerifierKey,
        instance: &Self::Instance,
    ) -> VerificationResult<()>;
}
```

`InteractiveReduction` takes the same three associated types. Simplest variant: index is fixed across a reduction (no `TargetIndex`); see open question 1.

This makes the IA side symmetric with `NonInteractiveArgument::Session` (`crates/ia-core/src/narg.rs:107`), which already documents itself as "public session/context data bound into the proof" — the existing precedent for a $\mathsf{vk}$-shaped slot at the NARG layer.

### 2. Backend: absorb $\mathsf{vk}$ before the first squeeze

CLAUDE.md invariant #2: public inputs must be absorbed before any challenge is squeezed. $\mathsf{vk}$ is a public input.

DSFS path: `crates/sigma-bridge/src/session.rs`. Live path: `crates/live-channel/src/lib.rs`. New shape:

```rust
let (pk, vk) = protocol.index(&index);

let mut domsep = DomainSeparator::new();
absorb_protocol_id(&mut domsep, protocol.protocol_id());
absorb_vk(&mut domsep, &vk);              // NEW
absorb_instance(&mut domsep, instance);
let mut prover = domsep.to_prover(Keccak::default());
protocol.prove(&mut prover, &pk, instance, witness);
```

Per the CLAUDE.md rule "if you change transcript/NARG layout, the DSFS-level `protocol_id` must change too," every protocol's `protocol_id` is bumped to tag the new layout. For protocols with `type Index = ()`, $\mathsf{vk}$ encodes to zero bytes (no observable absorb), but the `protocol_id` bump still signals the new format.

### 3. Trivially migrate non-indexed protocols

Schnorr, the sumcheck examples, all current sigma-bridge protocols:

```rust
type Index = ();
type ProverKey = ();
type VerifierKey = ();

fn index(&self, _: &()) -> ((), ()) { ((), ()) }
```

plus an unused arg on `prove` / `verify`. ~5-line diff per protocol plus the signature update.

### 4. Make `ArgumentSecurity` / `ReductionSecurity` index-aware

`crates/ia-core/src/security.rs`. CY24 Def 32.5.2 writes the size-bound as $\varepsilon(k, n)$ — index size *and* instance size. Split params/bounds:

```rust
pub trait ArgumentSecurity: InteractiveArgument {
    type IndexParams;     type IndexBound;
    type InstanceParams;  type InstanceBound;

    fn index_security_params(&self, ix: &Self::Index) -> Self::IndexParams;
    fn instance_security_params(
        &self, ix_params: &Self::IndexParams, inst: &Self::Instance,
    ) -> Self::InstanceParams;

    fn profile_for_instance_params(
        &self,
        ix_params: &Self::IndexParams,
        inst_params: &Self::InstanceParams,
    ) -> SecurityProfile;
    // bound variants analogous
}
```

Trivial protocols set `IndexParams = ()`. WARP's existing `WARPSecurityParams` (`crates/warp/src/protocol/ir.rs:42–60`) splits into `WARPIndexParams` (matrix sizes, code config, OOD/shift counts — all index-derived) and `WARPInstanceParams` (per-claim data).

### 5. Thread $\mathsf{vk}$ through composition

`crates/ia-core/src/compose.rs`. With "index fixed across the chain" (the simple option for open question 1):

```rust
impl<First, Second> InteractiveReduction for ChainedReduction<First, Second>
where
    First: InteractiveReduction,
    Second: InteractiveReduction<
        Index = First::Index,
        ProverKey = First::ProverKey,
        VerifierKey = First::VerifierKey,
        SourceInstance = First::TargetInstance,
        SourceWitness = First::TargetWitness,
    >,
{
    type Index = First::Index;
    type ProverKey = First::ProverKey;
    type VerifierKey = First::VerifierKey;

    fn index(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
        self.first.index(ix)
    }

    fn prove<P: ProverChannel>(
        &self, ch: &mut P, pk: &Self::ProverKey,
        instance: &Self::SourceInstance, witness: &Self::SourceWitness,
    ) -> (Self::TargetInstance, Self::TargetWitness) {
        let (x2, w2) = self.first.prove(ch, pk, instance, witness);
        self.second.prove(ch, pk, &x2, &w2)
    }
    // verify analogous
}
```

`ReducedArgument` gets the same treatment.

### 6. WARP refactor — retroactive grounding

Pull what is currently lumped inside `WARPInstance` apart along the index/pk/vk/instance lines:

```rust
struct WARPIndex<F, P, C, MT> {
    warp: WARPParams<F, P, C, MT>,   // code, config, MT params, constraint system
}

struct WARPProverKey<F, MT> {
    encoded_matrices: Vec<Codeword<F>>,
    matrix_trees: Vec<MerkleTree<MT>>,
}

struct WARPVerifierKey<MT> {
    matrix_roots: [MT::InnerDigest; 3],
    code_params: CodeConfig,
    constraint_count: usize,
}

struct WARPInstance<F> {
    instances: Vec<...>,
    acc_instances: Vec<...>,
}

impl InteractiveReduction for WARPReduction<...> {
    type Index = WARPIndex<F, P, C, MT>;
    type ProverKey = WARPProverKey<F, MT>;
    type VerifierKey = WARPVerifierKey<MT>;
    type SourceInstance = WARPInstance<F>;

    fn index(&self, ix: &WARPIndex<...>) -> (WARPProverKey<...>, WARPVerifierKey<...>) {
        // RS-encode A, B, C; build MT trees; emit roots.
    }
}
```

The destructuring at `ir.rs:121` becomes a direct read of `vk`.

### 7. Unblocks `crates/ibcs`

`crates/ibcs/src/lib.rs` is currently a stub. iBCS specifically needs to commit to an *index encoding* (the IOP's preprocessed oracle for V), so it cannot be implemented honestly without a place to put it. Step 1 provides the slot; iBCS becomes the first new protocol that uses indexed relations from day one.

## Migration order

1. Steps 1 + 3 in one PR (trait change + trivial protocols). Compiles; existing tests pass with `Index = ()`.
2. Step 2 in a follow-up PR (backend absorb + `protocol_id` bump). DSFS golden vectors updated.
3. Step 4 — independent, can land anytime after 1.
4. Step 5 — needed before any test that composes indexed protocols.
5. Step 6 — first real consumer.
6. Step 7 — first new protocol that needs this from day one.

## Open questions for advisors

1. **`TargetIndex` on reductions.** Arc IORs have an indexer that emits a new $\ell'$ on the verifier side. CY24 §32 has a fixed index. Do we expect any Argus reduction to *change* the index, or does "index fixed across the chain" cover everything we plan to build? The simplest trait surface assumes fixed; adding `TargetIndex` later is a breaking change.

2. **Indexer location.** Is `fn index(&self, ix) -> (pik, vik)` a method on the IA/IR trait, or a separate `Indexer` trait? Method form is one fewer trait bound and works fine if the indexer is unique per protocol. Separate trait matches the CY24 formalism literally and lets the same indexer be reused across protocols — does that ever happen in practice?

3. **Implicit instance $y$ (Arnon–Boneh–Fenzi).** This proposal does *not* address ABF's per-instance oracle handle (the encoded RS message in WARP); it is filed as a separate open question. Should the trait redesign address both at once with one $(\ell, x, y)$ shape, or land preprocessing first and treat $y$ as a follow-up?

4. **Holographic vs. fully-read $\mathsf{vik}$.** CY24 §32.1 has V read $\mathsf{vik}$ in full. Arc §5.1 has V query an oracle-encoded $\iota$. This proposal assumes full read ($\mathsf{vik}$ is small bytes). If iBCS / WHIR backends want oracle access to $\iota$, do we extend `VerifierKey` to support both modes, or treat oracle-$\mathsf{vik}$ as a separate protocol layer?

5. **Per-index `protocol_id`.** Should the `protocol_id` derivation include $\mathsf{vk}$'s hash (so different indices give different transcripts), or is the new "absorb $\mathsf{vk}$" step alone sufficient? Today's `protocol_id` is a static label per protocol; binding $\mathsf{vk}$ into it would tie the domain separator to the specific preprocessed instance.

## References

- CY24 §32.1 (preprocessing setting), §32.5 (HIOPs), §32.6 (SR for HIOPs).
- Arc 2024/1731 §5.1 (indexed oracle relations), §5.3 (BCS-style compilation).
- Arnon–Boneh–Fenzi 2026/680 §A.1 (IOR formalism with implicit instance $y$).
- `docs/adr/0003-instance-aware-security-metadata.md` (current security trait shape).
- CLAUDE.md: non-negotiable invariant #2 (public inputs before first challenge); `protocol_id` rule.
