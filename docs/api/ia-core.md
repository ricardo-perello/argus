# `ia-core`

`ia-core` is the protocol-facing API crate. Protocol authors should be able to
implement a protocol using this crate alone: no transcript internals, sponge
APIs, or DSFS-specific state.

## Core Tree

Argus uses explicit core traits as an inheritance spine:

```text
ProtocolCore
├── ArgumentCore
│   ├── InteractiveArgument
│   └── PreprocessingInteractiveArgument
└── ReductionCore
    ├── InteractiveReduction
    └── PreprocessingInteractiveReduction
```

`ProtocolCore` owns `protocol_id(&self)`. `ArgumentCore` owns `Instance` and
`Witness`. `ReductionCore` owns source/target instance and witness types.

`PreprocessingCore` is the preprocessing capability:

- `Index`
- `ProverKey`
- `VerifierKey: VerifierKeyCommitment`
- `index(ix) -> (pk, vk)`

Plain execution traits only contain channel logic. Preprocessing execution traits
receive `pk` or `vk` explicitly.

## Authoring Macros

Most protocol authors should write one macro block:

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
            instance: &Self::Instance,
            witness: &Self::Witness,
        ) {
            /* channel-only protocol logic */
        }

        fn verify<V: VerifierChannel>(
            &self,
            ch: &mut V,
            instance: &Self::Instance,
        ) -> VerificationResult<()> {
            /* channel-only protocol logic */
            Ok(())
        }
    }
}
```

Available macros:

- `impl_interactive_argument!`
- `impl_interactive_reduction!`
- `impl_preprocessing_argument!`
- `impl_preprocessing_reduction!`

The macros expand to normal impl blocks for `ProtocolCore`,
`ArgumentCore`/`ReductionCore`, `PreprocessingCore` when needed, and the
executable leaf trait. They support generic impl headers, optional `where`
clauses, and attributes on methods or associated types. Manual impls remain
part of the API.

## Core Traits

- `ProtocolCore`: protocol identity for domain separation.
- `ArgumentCore`: statement/witness shape for accept/reject protocols.
- `ReductionCore`: source/target relation shape for reductions.
- `PreprocessingCore`: preprocessing key-generation capability.
- `InteractiveArgument`: public-coin argument with accept/reject verifier.
- `InteractiveReduction`: public-coin reduction with verifier-produced target
  instance.
- `PreprocessingInteractiveArgument`: keyed/preprocessed argument authoring surface.
- `PreprocessingInteractiveReduction`: keyed/preprocessed reduction authoring surface.
- `ProverChannel`: prover-side channel interface.
- `VerifierChannel`: verifier-side channel interface.

## Prepared Preprocessing Protocols

`PreparedArgument<B>` and `PreparedReduction<B>` store keys produced by
`B::index(ix)`. They implement ordinary `InteractiveArgument` /
`InteractiveReduction` by pairing the per-claim instance with the committed
verifier index:

```rust
let prepared = PreparedArgument::prepare(body, &ix);
let indexed_instance = prepared.indexed_instance(instance);
```

The commitment comes from `vk.committed_index()`. `with_keys(body, pk, vk)`
derives the same commitment from `vk`; callers never provide a separate
commitment.

## Indexed Public Input

`CommittedIndexBytes` is the canonical public byte string for a verifier key.
`IndexedInstance<I>` and `IndexedInstanceRef<'_, I>` encode:

```text
tag || committed_index.encode()
    || u64_le(len(instance.encode())) || instance.encode()
```

DSFS uses `IndexedInstanceRef` internally so prepared non-interactive wrappers
can accept bare instances without cloning them.

## Proof Vocabulary

`ia-core` owns the abstract non-interactive vocabulary:

- `NargProof`
- `NonInteractiveArgument: ArgumentCore`
- `NonInteractiveReduction: ReductionCore`
- `PreprocessingNonInteractiveArgument`
- `PreprocessingNonInteractiveReduction`

The non-interactive traits inherit their statement/witness shape and
`protocol_id` from the same core tree as interactive protocols. They add only
`Session`, `prove`, and `verify`.

Concrete compilation to proof bytes is backend-owned.

## Source Layout

The crate is organized by layer:

```text
src/
  channel.rs
  core.rs
  interactive/
    argument.rs
    reduction.rs
    preprocessing.rs
    macros.rs
    composition/
      plain.rs
      preprocessing.rs
    adapters/
      preprocessing_to_plain.rs
      plain_to_preprocessing.rs
  noninteractive/
    argument.rs
    reduction.rs
    preprocessing.rs
    proof.rs
    adapters/
      narg_to_interactive.rs
  preprocessing/
  security/
```

`lib.rs` keeps the public imports flat, so consumers can continue importing
traits and helpers directly from `ia_core`.

## Composition

Use:

- `ChainedReduction` for `IR -> IR`
- `ReducedArgument` for `IR -> IA`

Composition derives protocol IDs and security metadata from the components.
Preprocessing composition is available when both components use preprocessing;
mixed composition uses `TrivialIndexedArgument` or `TrivialIndexedReduction`
explicitly.

## Security Metadata

- `ArgumentSecurity`
- `ReductionSecurity`
- `PreprocessingArgumentSecurity`
- `PreprocessingReductionSecurity`

The preprocessing variants separate index-derived security information from
per-instance security information.

## Protocol Implementation Rule

Inside protocol code, use only:

- `send_prover_message`
- `read_prover_message`
- `send_verifier_message`
- `read_verifier_message`

Do not instantiate sponges, derive challenges manually, or absorb public inputs
inside protocol implementations.
