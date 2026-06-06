# `ia-core`

`ia-core` is the protocol-facing API crate. Protocol authors should be able to
implement a protocol using this crate alone: no transcript internals, no sponge
APIs, and no DSFS-specific state.

## Core Traits

The common trait spine is:

```text
ProtocolCore
├── ArgumentCore
├── ReductionCore
└── PreprocessingCore
```

`ProtocolCore` provides:

```rust
fn protocol_id(&self) -> impl AsRef<[u8]>;
```

`ArgumentCore` provides `Instance` and `Witness`.

`ReductionCore` provides `SourceInstance`, `SourceWitness`,
`TargetInstance`, and `TargetWitness`.

`PreprocessingCore` provides:

```rust
type Index;
type ProverKey: CommittedIndex;
type VerifierKey: CommittedIndex;

fn preprocess(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey);
```

Preprocessing execution traits receive keys explicitly. They do not assume keys
live inside the protocol object.

## Interactive Leaves

Each leaf execution trait is split into a **prover half** (`prove`) and a
**verifier half** (`verify`), with the familiar full trait as their blanket-impl
conjunction:

| full trait | prover half | verifier half |
|---|---|---|
| `InteractiveArgument` | `InteractiveArgumentProver` | `InteractiveArgumentVerifier` |
| `InteractiveReduction` | `InteractiveReductionProver` | `InteractiveReductionVerifier` |
| `PreprocessingInteractiveArgument` | `PreprocessingInteractiveArgumentProver` | `PreprocessingInteractiveArgumentVerifier` |
| `PreprocessingInteractiveReduction` | `PreprocessingInteractiveReductionProver` | `PreprocessingInteractiveReductionVerifier` |

Authors normally don't touch the halves: the macro emits both from one block, and
any `T: InteractiveArgument` bound still resolves (the conjunction *is* both
halves). Bounding on a single half is what lets a backend build, hold, or demand
just one role. Most authors use the macro surface:

```rust
ia_core::impl_interactive_argument! {
    impl InteractiveArgument for MyProtocol {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            ia_core::pad_protocol_id(b"my-protocol")
        }

        type Instance = MyInstance;
        type Witness = MyWitness;

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

Available macros:

- `impl_interactive_argument!`
- `impl_interactive_reduction!`
- `impl_preprocessing_argument!`
- `impl_preprocessing_reduction!`

Manual impls are part of the API when adapters or tests need them. A genuinely
one-sided body just implements one half (e.g. only `InteractiveArgumentVerifier`)
and omits the other.

## Role Views and Recombination

- `into_prover()` / `into_verifier()` wrap a full body as a `ProverOnly<T>` /
  `VerifierOnly<T>` that exposes only one executable half. This is an *API*
  boundary — the wrapped body still implements both halves.
- `CombinedIA::new(prover_body, verifier_body)` is the inverse: glue a prover-only
  and a verifier-only body into a full `InteractiveArgument` (its NARG-level mirror
  is `spongefish_dsfs::CombinedNarg`).

The stateful `Prover` / `Verifier` key-binding wrappers are gone: capability
separation comes from the split, and preprocessing keys are passed explicitly to
`prove(&pk, …)` / `verify(&vk, …)`.

## Prelude

`use ia_core::prelude::*;` brings every leaf trait — each conjunction and both of
its halves, plus the core and channel traits — into scope, so a compiled object's
`.prove()` / `.verify()` resolve without listing each half. The conjunctions carry
no methods, so importing them beside the halves never causes ambiguity.

## Channels

Protocol implementations use:

- `ProverChannel`,
- `VerifierChannel`.

The byte-oriented DSFS path usually appears as:

```rust
fn prove<P: ProverChannel<Unit = u8>>(...)
fn verify<V: VerifierChannel<Unit = u8>>(...)
```

`Unit` is the channel alphabet. The concrete message type is chosen at each
send/read call.

## Non-Interactive Vocabulary

`ia-core` owns the abstract NARG vocabulary:

- `NargProof`,
- `NonInteractiveSession` (the shared `Session` associated type),
- `NonInteractiveArgument` (+ `…Prover` / `…Verifier` halves),
- `NonInteractiveReduction` (+ halves),
- `PreprocessingNonInteractiveArgument` (+ halves),
- `PreprocessingNonInteractiveReduction` (+ halves).

These split the same way as the interactive leaves. Concrete proof construction is
backend-owned: a backend implements the prover half under one bound and the
verifier half under another, so an interactive body that only proves compiles to a
prover-only NARG. In this workspace, `spongefish-dsfs` implements the DSFS compiler
backend.

## Preprocessing Public Input

`CommittedIndex` gives a backend canonical public bytes for an indexed relation:

```rust
pub trait CommittedIndex {
    fn committed_index(&self) -> CommittedIndexBytes;
}
```

Both preprocessing keys implement it. For matching keys produced by
`preprocess(ix)`, the committed-index bytes should agree. The
`preprocess_checked` helper debug-asserts that agreement.

`IndexedInstance` and `IndexedInstanceRef` are backend-facing wrappers that pair
committed-index bytes with the ordinary instance before transcript absorption.
Protocol code should not construct them manually.

## Composition

Use:

- `ChainedReduction` for `IR -> IR`,
- `ReducedArgument` for `IR -> IA`,
- `TrivialIndexedArgument` and `TrivialIndexedReduction` for explicit
  plain-to-preprocessing composition.

Composition also derives protocol IDs and security metadata from the component
protocols.

## Security Metadata

Security traits are opt-in:

- `ArgumentSecurity`,
- `ReductionSecurity`,
- `PreprocessingArgumentSecurity`,
- `PreprocessingReductionSecurity`.

The preprocessing variants separate index-derived information from per-instance
information.

## Protocol Implementation Rule

Inside protocol code, use only the channel API. Do not instantiate sponges,
derive challenges manually, absorb public inputs, or depend on proof byte
layout.
