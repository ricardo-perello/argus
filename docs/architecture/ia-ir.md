# Protocol Shapes

Argus covers a small matrix of public-coin protocol shapes:

| Axis | Choices |
| --- | --- |
| Verifier output | argument or reduction |
| Execution view | interactive or non-interactive |
| Static setup | plain or preprocessing |

Together these choices give eight combinations. The API is designed so the type
system exposes the capability a value actually has: a plain interactive argument
does not have preprocessing methods, while a preprocessing reduction carries
source/target relation types and keyed execution.

## Arguments and Reductions

An argument proves membership in one relation:

```text
R subset X x W
prover input:   x, w
verifier input: x
verifier output: accept/reject
```

A reduction transforms a source claim into a target claim:

```text
R0 -> R1
prover input:   x0, w0
prover output:  x1, w1
verifier input: x0
verifier output: x1
```

The verifier output is the important distinction. An argument is done when it
accepts. A reduction produces the next instance that another protocol may need
to prove or reduce.

## Plain and Preprocessing

Plain protocols receive all public statement data as the ordinary instance.

Preprocessing protocols split static relation data from per-claim data:

```text
preprocess(index) -> (prover_key, verifier_key)
prove(pk, instance, witness)
verify(vk, instance, proof)
```

The compiled preprocessing object is stateless with respect to keys. It stores
the protocol body and backend configuration, but it does not store a prover key
or verifier key. This keeps setup material explicit and prevents APIs from
quietly smuggling prover-only data into verifier-only code.

Both keys implement `CommittedIndex`. For keys derived from the same index,
their committed-index bytes must agree. DSFS binds those bytes together with the
ordinary instance before the first challenge.

## Trait Shape

The trait tree is bottom-up and capability-oriented:

```text
ProtocolCore
├── ArgumentCore
│   ├── InteractiveArgument
│   └── PreprocessingInteractiveArgument
└── ReductionCore
    ├── InteractiveReduction
    └── PreprocessingInteractiveReduction
```

`PreprocessingCore` is the shared setup capability used by preprocessing leaves.
It provides `Index`, `ProverKey`, `VerifierKey`, and `preprocess`.

This design was chosen over a single maximal protocol type that degenerates into
the simpler cases. The maximal type would reduce some generic machinery, but it
would also make irrelevant operations visible. In Argus, a plain protocol does
not pretend to be indexed, and a reduction is not forced to look like an
argument with a dummy output.

## Composition

Reductions compose sequentially when the target type of the first component
matches the source type of the second:

```text
R0 -> R1 -> R2
```

`ReducedArgument` composes a reduction with a final argument:

```text
R0 -> R1, then prove R1
```

Preprocessing composition pairs indexes and keys structurally:

```text
Index       = (First::Index, Second::Index)
ProverKey   = (First::ProverKey, Second::ProverKey)
VerifierKey = (First::VerifierKey, Second::VerifierKey)
```

The actual implementation pairs the first and second component types. The point
is that composition must route each sub-key to the corresponding component and
must bind a combined committed index before challenges. Mixed plain and
preprocessing composition is explicit through trivial-index adapters.

## Where Exact Signatures Live

This page explains the shape. Exact trait signatures, macro syntax, and source
layout are documented in [ia-core](../api/ia-core.md).
