# IA, IR, Indexed Bodies, and Composition

Argus now uses a small inheritance-style body tree. The root traits carry
protocol identity and relation shape; the leaf traits add executable protocol
logic.

```text
ProtocolBody
├── ArgumentBody
│   ├── InteractiveArgument
│   └── IndexedInteractiveArgument
└── ReductionBody
    ├── InteractiveReduction
    └── IndexedInteractiveReduction
```

`IndexedBody` is a sibling capability used by indexed leaves. It carries
`Index`, `ProverKey`, `VerifierKey`, and the deterministic `index(ix)` method.

## Body Traits

Every protocol body has a protocol identifier:

```rust
pub trait ProtocolBody {
    fn protocol_id(&self) -> impl AsRef<[u8]>;
}
```

Arguments add statement and witness types:

```rust
pub trait ArgumentBody: ProtocolBody {
    type Instance;
    type Witness;
}
```

Reductions add source and target relation types:

```rust
pub trait ReductionBody: ProtocolBody {
    type SourceInstance;
    type TargetInstance;
    type SourceWitness;
    type TargetWitness;
}
```

Indexed bodies add preprocessing:

```rust
pub trait IndexedBody: ProtocolBody {
    type Index;
    type ProverKey;
    type VerifierKey: VerifierKeyCommitment;

    fn index(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey);
}
```

## Executable Leaves

Plain arguments and reductions only contain channel execution methods. Their
identity and associated types come from the body traits.

```rust
pub trait InteractiveArgument: ArgumentBody {
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

```rust
pub trait InteractiveReduction: ReductionBody {
    fn prove<P: ProverChannel>(
        &self,
        ch: &mut P,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (Self::TargetInstance, Self::TargetWitness);

    fn verify<V: VerifierChannel>(
        &self,
        ch: &mut V,
        instance: &Self::SourceInstance,
    ) -> VerificationResult<Self::TargetInstance>;
}
```

Indexed leaves combine the argument/reduction body shape with `IndexedBody`.
Their execution methods receive keys explicitly:

```rust
pub trait IndexedInteractiveArgument: ArgumentBody + IndexedBody {
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

`IndexedInteractiveReduction` is the same idea for reductions.

## Prepared Adapters

Indexed bodies are not executable as plain IA/IR until keys exist.

```text
IndexedInteractiveArgument --prepare(ix)--> PreparedArgument
IndexedInteractiveReduction --prepare(ix)--> PreparedReduction
```

`PreparedArgument<B>` stores private `pk`, public `vk`, and
`vk.committed_index()`. It implements `InteractiveArgument` with:

```rust
type Instance = IndexedInstance<B::Instance>;
type Witness = B::Witness;
```

`PreparedReduction<B>` similarly implements `InteractiveReduction` with:

```rust
type SourceInstance = IndexedInstance<B::SourceInstance>;
```

Both prepared adapters reject an `IndexedInstance` whose committed index does
not match the stored verifier key.

## DSFS Constructors

The DSFS API names the non-interactive object being built:

```rust
let nia = dsfs::non_interactive_argument(body, dsfs::Keccak::default());
let nir = dsfs::non_interactive_reduction(body, dsfs::Keccak::default());
```

For plain bodies, the returned wrapper immediately implements
`NonInteractiveArgument` or `NonInteractiveReduction`.

For indexed bodies, call `.prepare(&ix)` first:

```rust
let nia = dsfs::non_interactive_argument(indexed_body, dsfs::Keccak::default())
    .prepare(&ix);
```

The prepared DSFS wrappers accept bare per-claim instances. Internally DSFS
absorbs `IndexedInstanceRef { committed_index, instance }` before the first
challenge, then calls keyed protocol execution with the bare instance.

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

Indexed composition is implemented when both components are indexed. The
composed index/key shape is a pair:

```rust
type Index = (First::Index, Second::Index);
type ProverKey = (First::ProverKey, Second::ProverKey);
type VerifierKey = (First::VerifierKey, Second::VerifierKey);
```

Mixed plain/indexed composition is explicit through `TrivialIndexedArgument`
and `TrivialIndexedReduction`. There is no blanket conversion that silently
turns plain protocols into indexed protocols.

## Security Composition

Plain security metadata remains on `ArgumentSecurity` and `ReductionSecurity`.
Indexed security metadata lives on `IndexedArgumentSecurity` and
`IndexedReductionSecurity`, with index-derived params/bounds separated from
per-instance params/bounds.

For composed protocols, security bounds are threaded through intermediate
relations. See [RBR and SR Soundness](../security/rbr-and-sr.md) and
[Instance-Aware Security](../security/instance-aware-security.md).
