# IA, IR, Preprocessing, and Composition

Argus now uses a small inheritance-style core tree. The root traits carry
protocol identity and relation shape; the leaf traits add executable protocol
logic.

```text
ProtocolCore
├── ArgumentCore
│   ├── InteractiveArgument
│   └── PreprocessingInteractiveArgument
└── ReductionCore
    ├── InteractiveReduction
    └── PreprocessingInteractiveReduction
```

`PreprocessingCore` is a sibling capability used by preprocessing leaves. It carries
`Index`, `ProverKey`, `VerifierKey`, and the deterministic `preprocess(ix)` method.

## Authoring Surface

Protocol authors normally write one macro block. For a plain argument:

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
            instance: &Self::Instance,
            witness: &Self::Witness,
        ) {
            /* channel-only prover logic */
        }

        fn verify<V: VerifierChannel<Unit = u8>>(
            &self,
            ch: &mut V,
            instance: &Self::Instance,
        ) -> VerificationResult<()> {
            /* channel-only verifier logic */
            Ok(())
        }
    }
}
```

For preprocessing arguments and reductions, use
`impl_preprocessing_argument!` or `impl_preprocessing_reduction!`; those blocks
also include `Index`, `ProverKey`, `VerifierKey`, and `preprocess(ix)`.

The macros expand to the core tree below. The split traits are real API, not a
macro illusion, so backend and composition code can reason about capabilities
precisely while authors avoid three or four repetitive impl blocks.

## Core Traits

Every protocol core has a protocol identifier:

```rust
pub trait ProtocolCore {
    fn protocol_id(&self) -> impl AsRef<[u8]>;
}
```

Arguments add statement and witness types:

```rust
pub trait ArgumentCore: ProtocolCore {
    type Instance;
    type Witness;
}
```

Reductions add source and target relation types:

```rust
pub trait ReductionCore: ProtocolCore {
    type SourceInstance;
    type TargetInstance;
    type SourceWitness;
    type TargetWitness;
}
```

Preprocessing cores add preprocessing:

```rust
pub trait PreprocessingCore: ProtocolCore {
    type Index;
    type ProverKey: CommittedIndex;
    type VerifierKey: CommittedIndex;

    fn preprocess(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey);

    fn preprocess_checked(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
        /* calls preprocess, then debug-asserts matching committed_index() bytes */
    }
}
```

## Executable Leaves

Plain arguments and reductions only contain channel execution methods. Their
identity and associated types come from the core traits.

```rust
pub trait InteractiveArgument: ArgumentCore {
    fn prove<P: ProverChannel<Unit = u8>>(
        &self,
        ch: &mut P,
        instance: &Self::Instance,
        witness: &Self::Witness,
    );

    fn verify<V: VerifierChannel<Unit = u8>>(
        &self,
        ch: &mut V,
        instance: &Self::Instance,
    ) -> VerificationResult<()>;
}
```

```rust
pub trait InteractiveReduction: ReductionCore {
    fn prove<P: ProverChannel<Unit = u8>>(
        &self,
        ch: &mut P,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (Self::TargetInstance, Self::TargetWitness);

    fn verify<V: VerifierChannel<Unit = u8>>(
        &self,
        ch: &mut V,
        instance: &Self::SourceInstance,
    ) -> VerificationResult<Self::TargetInstance>;
}
```

Preprocessing leaves combine the argument/reduction body shape with `PreprocessingCore`.
Their execution methods receive keys explicitly:

```rust
pub trait PreprocessingInteractiveArgument: ArgumentCore + PreprocessingCore {
    fn prove<P: ProverChannel<Unit = u8>>(
        &self,
        ch: &mut P,
        pk: &Self::ProverKey,
        instance: &Self::Instance,
        witness: &Self::Witness,
    );

    fn verify<V: VerifierChannel<Unit = u8>>(
        &self,
        ch: &mut V,
        vk: &Self::VerifierKey,
        instance: &Self::Instance,
    ) -> VerificationResult<()>;
}
```

`PreprocessingInteractiveReduction` is the same idea for reductions.

## Preprocessing Keys as Inputs

Preprocessing cores are executable only with keys. The same body exposes:

```text
preprocess(ix) -> (ProverKey, VerifierKey)
prove(ch, &ProverKey, instance, witness)
verify(ch, &VerifierKey, instance)
```

Both key types implement `CommittedIndex`. The compiled backend derives
`pk.committed_index()` on the prover side and `vk.committed_index()` on the
verifier side. `preprocess_checked(&ix)` catches mismatched key commitments in
debug/test builds while both keys are in hand.

## DSFS Constructors

The DSFS API names the non-interactive object being built:

```rust
let nia = dsfs::plain_non_interactive_argument(body, dsfs::Keccak::default());
let nir = dsfs::plain_non_interactive_reduction(body, dsfs::Keccak::default());
```

For plain bodies, the returned wrapper immediately implements
`NonInteractiveArgument` or `NonInteractiveReduction`.

For preprocessing cores, the returned wrapper is stateless and implements
`PreprocessingNonInteractiveArgument` or `PreprocessingNonInteractiveReduction`.
Call `.preprocess(&ix)` to obtain keys, then pass the relevant key into
`prove` or `verify`:

```rust
let nia = dsfs::preprocessing_non_interactive_argument(preprocessing_protocol, dsfs::Keccak::default());
let (pk, vk) = nia.preprocess(&ix);
let proof = nia.prove(&pk, &session, &instance, &witness);
nia.verify(&vk, &session, &instance, &proof)?;
```

Internally DSFS absorbs `IndexedInstanceRef { committed_index, instance }`
before the first challenge, then calls keyed protocol execution with the bare
instance.

## Composition

`ChainedReduction<First, Second>` composes two reductions:

```text
IR1: R0 -> R1
IR2: R1 -> R2
IR2 after IR1: R0 -> R2
```

`ReducedArgument<Reduction, Argument>` composes a reduction with a final
argument:

```text
IR: R0 -> R1
IA: proves R1
IR followed by IA: proves R0
```

Composition derives protocol IDs using injective length-prefixed encoding, so
nested protocols remain domain-separated.

Preprocessing composition is implemented when both components use preprocessing. The
composed index/key shape is a pair:

```rust
type Index = (First::Index, Second::Index);
type ProverKey = (First::ProverKey, Second::ProverKey);
type VerifierKey = (First::VerifierKey, Second::VerifierKey);
```

Mixed plain/preprocessing composition is explicit through `TrivialIndexedArgument`
and `TrivialIndexedReduction`. There is no blanket conversion that silently
turns plain protocols into preprocessing protocols.

## Security Composition

Plain security metadata remains on `ArgumentSecurity` and `ReductionSecurity`.
Indexed security metadata lives on `PreprocessingArgumentSecurity` and
`PreprocessingReductionSecurity`, with index-derived params/bounds separated from
per-instance params/bounds.

For composed protocols, security bounds are threaded through intermediate
relations. See [RBR and SR Soundness](../security/rbr-and-sr.md) and
[Instance-Aware Security](../security/instance-aware-security.md).
