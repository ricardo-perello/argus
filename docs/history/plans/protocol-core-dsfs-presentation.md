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
├── ProverKey: CommittedIndex
├── VerifierKey: CommittedIndex
├── preprocess(ix) -> (pk, vk)
└── preprocess_checked(ix) -> (pk, vk)
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

        fn prove<P: ProverChannel<Unit = u8>>(
            &self,
            ch: &mut P,
            x: &Self::Instance,
            w: &Self::Witness,
        ) {
            ...
        }

        fn verify<V: VerifierChannel<Unit = u8>>(
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

        fn preprocess(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
            ...
        }

        fn prove<P: ProverChannel<Unit = u8>>(
            &self,
            ch: &mut P,
            pk: &Self::ProverKey,
            x: &Self::SourceInstance,
            w: &Self::SourceWitness,
        ) -> (Self::TargetInstance, Self::TargetWitness) {
            ...
        }

        fn verify<V: VerifierChannel<Unit = u8>>(
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
let nia = dsfs::preprocessing_non_interactive_argument(preprocessing_argument, dsfs::Keccak::default());
let (pk, vk) = nia.preprocess(&index);
let proof = nia.prove(&pk, &session, &instance, &witness);
nia.verify(&vk, &session, &instance, &proof)?;
```

Preprocessing reduction:

```rust
let nir = dsfs::preprocessing_non_interactive_reduction(preprocessing_reduction, dsfs::Keccak::default());
let (pk, vk) = nir.preprocess(&index);
let (proof, target, target_witness) = nir.prove(&pk, &session, &source, &witness);
let verified_target = nir.verify(&vk, &session, &source, &proof)?;
```

The concrete wrapper names are `DsfsArgument`, `DsfsReduction`,
`PreprocessedDsfsArgument`, and `PreprocessedDsfsReduction`, but user code reads
as "construct a non-interactive argument/reduction" with the preprocessing
flavor spelled out in the constructor name.

## 5. Keys as Inputs

The preprocessing DSFS wrappers are stateless:

```text
preprocessing_non_interactive_argument(body, sponge)
  -> PreprocessedDsfsArgument { body, sponge }   // no keys

PreprocessedDsfsArgument::preprocess(ix)
  -> body.preprocess_checked(ix)
  -> (pk, vk)
```

Proving and verification receive keys explicitly:

```text
pnia.prove (&pk, session, x, w)
pnia.verify(&vk, session, x, proof)
```

The optional role wrappers are only convenience views over `(narg, key)`:

```text
Prover::new(&pnia, &pk)      // exposes prove
Verifier::new(&pnia, &vk)    // exposes verify
```

## 6. Transcript Binding

Plain DSFS absorbs:

```text
DomainSeparator::derive(protocol_id, sponge_info, session)
    .instance(instance)
```

Preprocessing DSFS absorbs:

```text
DomainSeparator::derive(protocol_id, sponge_info, session)
    .instance(IndexedInstanceRef { committed_index: key.committed_index(), instance })
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
`Index = WarpIndex`, so callers run `preprocess(&ix)`, not
`preprocess(&(ix, ix))`.

This removes the old reach-through where prover code read `instance.pk` and the
verifier reconstructed `vk` from `instance.pk`, and it removes the temporary
tuple-index composition workaround.

## 10. Review Claims

- Plain DSFS proof bytes are not intentionally changed.
- DSFS remains the only layer that touches sponge operations.
- Protocol code still uses only the channel API.
- Preprocessing is key generation plus keyed execution, not a standalone
  `Indexer` bolted onto plain protocols.
- Preprocessing wrappers bind `pk.committed_index()` on the prover side and
  `vk.committed_index()` on the verifier side before the first challenge.
- `preprocess_checked` debug-asserts that keys produced from the same index have
  matching committed-index bytes.
