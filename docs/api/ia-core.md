# `ia-core`

`ia-core` is the protocol-facing API crate. Protocol code depends on channel
traits and role interfaces, never transcript internals.

## Core Traits

```text
ProtocolCore
├── ArgumentCore              (Instance)
│   └── ArgumentProverCore    (Witness)
├── ReductionCore             (SourceInstance, TargetInstance)
│   └── ReductionProverCore   (SourceWitness, TargetWitness)
└── Indexer                   (Index, ProverKey, VerifierKey)
```

`Indexer::preprocess_checked` returns
`Result<(ProverKey, VerifierKey), IndexingError>` and rejects committed-index
mismatches in all build modes.

## Executable Roles

Plain roles:

- `InteractiveArgumentProver`
- `InteractiveArgumentVerifier`
- `InteractiveReductionProver`
- `InteractiveReductionVerifier`

Preprocessing roles:

- `PreprocessingInteractiveArgumentProver`
- `PreprocessingInteractiveArgumentVerifier`
- `PreprocessingInteractiveReductionProver`
- `PreprocessingInteractiveReductionVerifier`

Each preprocessing executable trait owns only its role-specific key type. There
are no full conjunction traits, role views, or recombination adapters.

## Authoring Macros

Each invocation authors one native role:

```rust
ia_core::impl_interactive_argument! {
    prover impl for MyProver {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            ia_core::pad_protocol_id(b"my-protocol")
        }

        type Instance = MyInstance;
        type Witness = MyWitness;

        fn prove<C: ProverChannel<Unit = u8>>(
            &self,
            channel: &mut C,
            instance: &Self::Instance,
            witness: &Self::Witness,
        ) {
            // Channel-only prover logic.
        }
    }
}
```

The `verifier` form omits witness types. Preprocessing macros also accept an
`indexer` form. Argument indexers declare `Instance`; reduction indexers declare
`SourceInstance` and `TargetInstance`, allowing security metadata to live on the
indexer.

Available macros:

- `impl_interactive_argument!`
- `impl_interactive_reduction!`
- `impl_preprocessing_argument!`
- `impl_preprocessing_reduction!`

## Non-Interactive Vocabulary

The compiled role traits mirror the interactive roles:

- `NonInteractiveArgumentProver` / `NonInteractiveArgumentVerifier`
- `NonInteractiveReductionProver` / `NonInteractiveReductionVerifier`
- preprocessing argument and reduction prover/verifier variants

`NargProof` and `NonInteractiveSession` are shared vocabulary. Concrete proof
construction belongs to a backend such as `spongefish-dsfs`.

`NargProverAsInteractiveArgument` and
`NargVerifierAsInteractiveArgument` expose compiled roles as one-message
interactive roles without recombining them.

## Composition and Security

Use `ChainedReduction` for reduction composition and `ReducedArgument` for a
reduction followed by an argument. Instantiate them independently for prover,
verifier, and indexer roles.

Plain security metadata is implemented on verifier types:

- `ArgumentSecurity`
- `ReductionSecurity`

Preprocessing security metadata is implemented on indexer types:

- `PreprocessingArgumentSecurity`
- `PreprocessingReductionSecurity`

Inside protocol code, use only `ProverChannel` and `VerifierChannel`.
