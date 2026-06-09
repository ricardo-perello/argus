# Protocol Shapes

Argus covers public-coin arguments and reductions, with plain or preprocessing
execution. Proving, verification, and indexing are independent production roles,
so each deployed type exposes only the capability it actually has.

## Arguments and Reductions

An argument proves membership in one relation:

```text
R subset X x W
prover input:    x, w
verifier input:  x
verifier output: accept/reject
```

A reduction transforms a source claim into a target claim:

```text
R0 -> R1
prover input:    x0, w0
prover output:   x1, w1
verifier input:  x0
verifier output: x1
```

## Plain and Preprocessing

Plain protocols receive all public statement data as the instance.
Preprocessing protocols use three independent roles:

```text
indexer.preprocess(index)
    -> (prover_key, verifier_key)
prover.prove(pk, instance, witness)
verifier.verify(vk, instance)
```

Both keys implement `CommittedIndex`. The indexer contract requires equal
committed-index bytes for keys derived from the same index. DSFS binds the
role's key commitment together with the ordinary instance before the first
challenge; violating the contract makes the transcripts diverge.

## Trait Shape

Public statement shape and prover-private shape are separate:

```text
ProtocolCore
├── ArgumentCore
│   ├── ArgumentProverCore
│   │   ├── InteractiveArgumentProver
│   │   └── PreprocessingInteractiveArgumentProver
│   ├── InteractiveArgumentVerifier
│   └── PreprocessingInteractiveArgumentVerifier
└── ReductionCore
    ├── ReductionProverCore
    │   ├── InteractiveReductionProver
    │   └── PreprocessingInteractiveReductionProver
    ├── InteractiveReductionVerifier
    └── PreprocessingInteractiveReductionVerifier

ProtocolCore
└── Indexer
```

Each role is authored on its own concrete type. There are no full conjunction
traits, role-view wrappers, or recombination adapters. Verifiers therefore have
no witness or prover-key associated type, and indexers have no executable
method.

Plain security metadata is implemented on verifier roles. Preprocessing
security metadata is implemented on indexer roles.

## Composition

`ChainedReduction` composes reductions when the first target instance matches
the second source instance. `ReducedArgument` composes a reduction with a final
argument.

Each composition is instantiated separately for prover, verifier, and indexer
roles. Prover composition carries witness equalities; verifier composition only
needs public instance equalities. Indexer composition pairs indexes and keys:

```text
Index       = (First::Index, Second::Index)
ProverKey   = (First::ProverKey, Second::ProverKey)
VerifierKey = (First::VerifierKey, Second::VerifierKey)
```

Mixed plain and preprocessing composition uses role-specific trivial-index
adapters.

Exact signatures, macro forms, DSFS wrappers, and migration rationale are in the
[role-first architecture plan](role-first-protocol-architecture-plan.md).
