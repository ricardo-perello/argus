# Protocol Core Tree and DSFS Constructors

**Audience:** Giacomo / Chiesa implementation review.

**Status:** Current code shape on the preprocessing branch.

## 1. The Inheritance Tree

```text
ProtocolCore
├── ArgumentCore
│   ├── InteractiveArgument
│   └── PreprocessingInteractiveArgument
└── ReductionCore
    ├── InteractiveReduction
    └── PreprocessingInteractiveReduction
```

`PreprocessingCore` is the preprocessing capability shared by both preprocessing leaves:

```text
PreprocessingCore
├── Index
├── ProverKey
├── VerifierKey: VerifierKeyCommitment
└── index(ix) -> (pk, vk)
```

The effect is deliberately OOP-ish: common identity lives at the root, common
argument/reduction shape lives in the middle, and executable capabilities live
at the leaves.

## 2. What Plain Authors Write

Plain Schnorr-style protocols write one coherent authoring block:

```rust
ia_core::impl_interactive_argument! {
    impl InteractiveArgument for Schnorr {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            ia_core::pad_protocol_id(b"schnorr")
        }

        type Instance = SchnorrInstance;
        type Witness = SchnorrWitness;

        fn prove<P: ProverChannel>(
            &self,
            ch: &mut P,
            x: &Self::Instance,
            w: &Self::Witness,
        ) {
            ...
        }

        fn verify<V: VerifierChannel>(
            &self,
            ch: &mut V,
            x: &Self::Instance,
        ) -> VerificationResult<()> {
            ...
        }
    }
}
```

The macro expands to `ProtocolCore`, `ArgumentCore`, and
`InteractiveArgument`. Manual split impls remain available, but the default
authoring path is no longer three blocks of ceremony.

The execution methods contain only channel operations. Protocol code still does
not absorb public input, instantiate a sponge, derive Fiat-Shamir challenges, or
know whether it is running live or non-interactively.

## 3. What Preprocessing Authors Write

WARP-style or preprocessing-style protocols use the preprocessing macro. The
same block includes key generation and keyed execution:

```rust
ia_core::impl_preprocessing_reduction! {
    impl PreprocessingInteractiveReduction for WarpReduction {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            ia_core::pad_protocol_id(b"warp-reduction")
        }

        type SourceInstance = WarpInstance;
        type TargetInstance = DeciderInstance;
        type SourceWitness = WarpWitness;
        type TargetWitness = DeciderWitness;

        type Index = WarpIndex;
        type ProverKey = WarpProverKey;
        type VerifierKey = WarpVerifierKey;

        fn index(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
            ...
        }

        fn prove<P: ProverChannel>(
            &self,
            ch: &mut P,
            pk: &Self::ProverKey,
            x: &Self::SourceInstance,
            w: &Self::SourceWitness,
        ) -> (Self::TargetInstance, Self::TargetWitness) {
            ...
        }

        fn verify<V: VerifierChannel>(
            &self,
            ch: &mut V,
            vk: &Self::VerifierKey,
            x: &Self::SourceInstance,
        ) -> VerificationResult<Self::TargetInstance> {
            ...
        }
    }
}
```

This expands to `ProtocolCore`, `ReductionCore`, `PreprocessingCore`, and
`PreprocessingInteractiveReduction`.

This fixes the original indexer-only flaw: key generation alone is not enough.
The protocol surface must also give `prove` the prover key and `verify` the
verifier key.

## 4. DSFS Looks Like Constructing a NARG

Plain argument:

```rust
let nia = dsfs::plain_non_interactive_argument(schnorr, dsfs::Keccak::default());
let proof = nia.prove(&session, &instance, &witness);
nia.verify(&session, &instance, &proof)?;
```

Plain reduction:

```rust
let nir = dsfs::plain_non_interactive_reduction(reduction, dsfs::Keccak::default());
let (proof, target, target_witness) = nir.prove(&session, &source, &witness);
let verified_target = nir.verify(&session, &source, &proof)?;
```

Preprocessing argument:

```rust
let nia = dsfs::preprocessing_non_interactive_argument(preprocessing_argument, dsfs::Keccak::default())
    .prepare(&index);
```

Preprocessing reduction:

```rust
let nir = dsfs::preprocessing_non_interactive_reduction(preprocessing_reduction, dsfs::Keccak::default())
    .prepare(&index);
```

The concrete wrapper names are `DsfsArgument`, `DsfsReduction`,
`UnpreparedDsfsArgument`, `UnpreparedDsfsReduction`, `PreparedDsfsArgument`,
and `PreparedDsfsReduction`, but user code reads as "construct a
non-interactive argument/reduction" with the lifecycle stage spelled out in the
constructor name.

## 5. Prepared Objects

Preparation stores keys:

```text
prepare(ix)
  -> body.index(ix)
  -> stores pk, vk, vk.committed_index()
```

Prepared IA/IR adapters exist at the `ia-core` layer:

```text
PreparedArgument<B>: InteractiveArgument
PreparedReduction<B>: InteractiveReduction
```

Prepared DSFS wrappers exist at the backend layer:

```text
UnpreparedDsfsArgument<B>: prepare(ix) -> PreparedDsfsArgument<B>
UnpreparedDsfsReduction<B>: prepare(ix) -> PreparedDsfsReduction<B>
PreparedDsfsArgument<B>: NonInteractiveArgument + Preprocessed
PreparedDsfsReduction<B>: NonInteractiveReduction + Preprocessed
```

`Preprocessed` is the common capability for inspecting stored keys:

```rust
fn prover_key(&self) -> &Self::ProverKey;
fn verifier_key(&self) -> &Self::VerifierKey;
fn committed_index(&self) -> &CommittedIndexBytes;
```

## 6. Transcript Binding

Plain DSFS absorbs:

```text
DomainSeparator::derive(protocol_id, sponge_info, session)
    .instance(instance)
```

Prepared DSFS absorbs:

```text
DomainSeparator::derive(protocol_id, sponge_info, session)
    .instance(IndexedInstanceRef { committed_index, instance })
```

Then execution uses the bare instance:

```text
body.prove(ch, pk, instance, witness)
body.verify(ch, vk, instance)
```

So the committed verifier key and public instance are fixed before the first
challenge, while protocol code never touches transcript internals.

## 7. Composition

Plain composition is unchanged:

```text
ChainedReduction<IR1, IR2>: IR
ReducedArgument<IR, IA>: IA
```

Preprocessing composition exists when both components use preprocessing:

```rust
type Index = (First::Index, Second::Index);
type ProverKey = (First::ProverKey, Second::ProverKey);
type VerifierKey = (First::VerifierKey, Second::VerifierKey);
```

Verifier-key commitments are composed with a canonical tagged pair encoding.
Mixed plain/preprocessing composition requires an explicit `TrivialIndexedArgument`
or `TrivialIndexedReduction`, making the empty verifier-index commitment a
visible author choice.

## 8. Security Metadata

Plain protocols keep:

```text
ArgumentSecurity
ReductionSecurity
```

Preprocessing protocols use:

```text
PreprocessingArgumentSecurity
PreprocessingReductionSecurity
```

The preprocessing security traits separate:

```text
index-derived params/bounds
per-instance params/bounds
```

For WARP this matters: code parameters, dimensions, OOD samples, and shift
queries are index-derived; individual accumulated claims are per-instance.

## 9. WARP Shape

WARP is now represented as:

```text
WarpIndex        static relation/config/code data
WarpProverKey    prover-side preprocessed data
WarpVerifierKey  verifier-side compact metadata and commitment bytes
WarpInstance     per-claim instances/accumulators
WarpWitness      per-claim witnesses
```

`WarpReduction` implements `PreprocessingInteractiveReduction`.
`WarpDecider` implements `PreprocessingInteractiveArgument`.
`FullWarp` is itself a preprocessing argument with a single
`Index = WarpIndex`, so callers prepare it with `prepare(&ix)`, not
`prepare(&(ix, ix))`.

This removes the old reach-through where prover code read `instance.pk` and the
verifier reconstructed `vk` from `instance.pk`, and it removes the temporary
tuple-index composition workaround.

## 10. Review Claims

- Plain DSFS proof bytes are not intentionally changed.
- DSFS remains the only layer that touches sponge operations.
- Protocol code still uses only the channel API.
- Preprocessing is key generation plus keyed execution, not a standalone
  `Indexer` bolted onto plain protocols.
- Prepared wrappers bind `vk.committed_index()` before the first challenge.
- `with_keys(pk, vk)` derives the cached commitment from `vk`, preventing
  commitment/key desynchronization.
