# `ia-core`

`ia-core` is the protocol-facing API crate.

Protocol authors should be able to implement a protocol using this crate alone.
They should not need transcript internals, sponge APIs, or DSFS-specific state.

## Core Traits

- `InteractiveArgument`: public-coin argument with accept/reject verifier.
- `InteractiveReduction`: public-coin reduction with verifier-produced target
  instance.
- `ProverChannel`: prover-side channel interface.
- `VerifierChannel`: verifier-side channel interface.
- `ArgumentSecurity`: instance-aware argument security metadata.
- `ReductionSecurity`: instance-aware reduction security metadata.

## Proof Vocabulary

`ia-core` owns the abstract non-interactive vocabulary:

- `NargProof`,
- `NonInteractiveArgument`,
- `NonInteractiveReduction`.

Concrete compilation to proof bytes is backend-owned.

## Composition

Use:

- `ChainedReduction` for `IR -> IR`,
- `ReducedArgument` for `IR -> IA`.

Composition derives protocol IDs and security metadata from the components.

## Protocol Implementation Rule

Inside protocol code, use only:

- `send_prover_message`,
- `read_prover_message`,
- `send_verifier_message`,
- `read_verifier_message`.

Do not instantiate sponges, derive challenges manually, or absorb public inputs
inside protocol implementations.
