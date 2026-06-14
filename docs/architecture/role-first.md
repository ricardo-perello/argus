# Role-First Architecture

Argus authors every protocol as **independent prover, verifier, and indexer
roles**, each on its own concrete type. A deployed type exposes only the
capability it has: a verifier has no witness or prover-key associated type, an
indexer has no executable `prove`/`verify`, and there are no "full" conjunction
traits or role-recombination wrappers.

This is the current, shipped reference. For the migration history and rationale
that produced it, see the archived
[Role-First Architecture Record](../history/plans/role-first-protocol-architecture-plan.md).
For the compile-then-prove runtime lifecycle, see
[DSFS: compile, then prove](../author-guide/compile-and-prove.md).

## Trait tree

Public-statement shape (`*Core`) and prover-private shape (`*ProverCore`) are
separate, so verifier roles never name a witness:

```text
ProtocolCore                      // protocol_id() — domain separation
├── ArgumentCore                  // type Instance
│   ├── ArgumentProverCore        // type Witness
│   │   ├── InteractiveArgumentProver
│   │   └── PreprocessingInteractiveArgumentProver        // + type ProverKey
│   ├── InteractiveArgumentVerifier
│   └── PreprocessingInteractiveArgumentVerifier          // + type VerifierKey
└── ReductionCore                 // type SourceInstance, type TargetInstance
    ├── ReductionProverCore       // type SourceWitness, type TargetWitness
    │   ├── InteractiveReductionProver
    │   └── PreprocessingInteractiveReductionProver        // + type ProverKey
    ├── InteractiveReductionVerifier
    └── PreprocessingInteractiveReductionVerifier          // + type VerifierKey

ProtocolCore
└── Indexer                       // preprocess(index) -> (ProverKey, VerifierKey)
```

The `Interactive*` traits are **the algorithm you write** (they take a channel).
Compiling them yields the `NonInteractive*` counterparts
(`NonInteractiveArgumentProver`, `PreprocessingNonInteractiveArgumentVerifier`,
…) plus `NonInteractiveSession` — these are what a backend implements, not the
author.

## Authoring a role

Implement the leaf trait directly, or use the authoring macros in `ia-core`,
which generate the `*Core` spine plus the executable leaf from one block:

| | argument | reduction |
| --- | --- | --- |
| plain prover | `impl_interactive_argument_prover!` | `impl_interactive_reduction_prover!` |
| plain verifier | `impl_interactive_argument_verifier!` | `impl_interactive_reduction_verifier!` |
| plain pair | `impl_interactive_argument!` | `impl_interactive_reduction!` |
| preprocessing prover | `impl_preprocessing_argument_prover!` | `impl_preprocessing_reduction_prover!` |
| preprocessing verifier | `impl_preprocessing_argument_verifier!` | `impl_preprocessing_reduction_verifier!` |
| preprocessing indexer | `impl_preprocessing_argument_indexer!` | `impl_preprocessing_reduction_indexer!` |
| preprocessing pair | `impl_preprocessing_argument!` | `impl_preprocessing_reduction!` |

Protocol bodies only use the channel API (`send_prover_message` /
`read_verifier_message`; `read_prover_message` / `send_verifier_message`). They
never instantiate a sponge or derive a challenge.

## Compiling with DSFS (Scheme B API)

The compiler is `spongefish-dsfs`. The **module path** marks the axis (plain at
the crate root, preprocessing under `preprocessing`); the **leaf name** marks the
role. `NonInteractive` and the backend name are implied, so they are not in the
identifier.

| role | plain type / constructor | preprocessing type / constructor |
| --- | --- | --- |
| arg prover | `ArgumentProver` / `argument_prover` | `preprocessing::ArgumentProver` / `preprocessing::argument_prover` |
| arg verifier | `ArgumentVerifier` / `argument_verifier` | `preprocessing::ArgumentVerifier` / `preprocessing::argument_verifier` |
| reduction prover | `ReductionProver` / `reduction_prover` | `preprocessing::ReductionProver` / `preprocessing::reduction_prover` |
| reduction verifier | `ReductionVerifier` / `reduction_verifier` | `preprocessing::ReductionVerifier` / `preprocessing::reduction_verifier` |

Each constructor has a `*_with_salt::<…, SALT_LEN>` variant. Compilation is a
`const fn` that only wraps the role body together with a sponge **template**; the
transcript is created (and destroyed) per `.prove` / `.verify` call.

```rust,ignore
use spongefish_dsfs as dsfs;

// plain
let prover   = dsfs::argument_prover(MyProver,   dsfs::Keccak::default());
let verifier = dsfs::argument_verifier(MyVerifier, dsfs::Keccak::default());
let proof = prover.prove(&session, &instance, &witness);
verifier.verify(&session, &instance, &proof)?;

// preprocessing — keys come from an independent indexer and are passed per call
let (pk, vk) = indexer.preprocess(&index);
let prover   = dsfs::preprocessing::argument_prover(MyProver,   dsfs::Keccak::default());
let verifier = dsfs::preprocessing::argument_verifier(MyVerifier, dsfs::Keccak::default());
let proof = prover.prove(&pk, &session, &instance, &witness);
verifier.verify(&vk, &session, &instance, &proof)?;
```

DSFS does not forward `Indexer` and does not provide a combined compiled object.
The sponge defaults to `Keccak` (the analyzed setting); `StdHash` is available
for `sigma-proofs` byte-compatibility (its bounds are heuristic).

## Composition

- `ChainedReduction` chains two reductions when the first target instance matches
  the second source instance.
- `ReducedArgument` chains a reduction with a final argument.

Each is instantiated separately for the prover, verifier, and indexer roles:
prover composition carries witness equalities, verifier composition only the
public-instance equalities, and indexer composition pairs indexes/keys
(`Index = (First::Index, Second::Index)`, likewise `ProverKey` / `VerifierKey`).
Mixing plain and preprocessing protocols uses the role-specific trivial-index
adapters. A compiled NARG verifier can be re-fed as a one-message interactive
argument via the NARG-to-interactive adapters (the recursion building block).

## Security metadata

Security profiles are separate from execution. Plain security metadata is
implemented on **verifier** roles (`ArgumentSecurity`, `ReductionSecurity`);
preprocessing security metadata is implemented on **indexer** roles. Backends
consume these profiles to evaluate DSFS bounds; transcript invariants remain a
backend responsibility, never the author's.
