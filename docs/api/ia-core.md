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

`Indexer::preprocess` returns `(ProverKey, VerifierKey)`. Implementations must
ensure both keys produce identical `CommittedIndex` bytes. DSFS binds those
bytes independently on the proving and verification paths, so violating the
contract makes every proof fail to verify.

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

The short macros author related native roles from one shared declaration:

```rust,ignore
ia_core::impl_interactive_argument! {
    impl {
        prover: MyProver,
        verifier: MyVerifier,
    }
    {
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

        fn verify<C: VerifierChannel<Unit = u8>>(
            &self,
            channel: &mut C,
            instance: &Self::Instance,
        ) -> VerificationResult<()> {
            // Channel-only verifier logic.
        }
    }
}
```

The macro emits independent prover and verifier implementations. Witness types
and `prove` are routed only to the prover; `verify` is routed only to the
verifier. Preprocessing shared macros similarly emit an independent indexer.

Shared macros:

- `impl_interactive_argument!`
- `impl_interactive_reduction!`
- `impl_preprocessing_argument!`
- `impl_preprocessing_reduction!`

Use the role-specific suffix forms when roles need different generic bounds or
live in separate modules:

- `impl_interactive_argument_prover!` / `impl_interactive_argument_verifier!`
- `impl_interactive_reduction_prover!` / `impl_interactive_reduction_verifier!`
- `impl_preprocessing_argument_indexer!`,
  `impl_preprocessing_argument_prover!`, and
  `impl_preprocessing_argument_verifier!`
- the corresponding `impl_preprocessing_reduction_*` macros

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
