# Protocol Types

Argus protocols are classified by verifier output and setup shape. Proving,
verification, and indexing are independent capabilities.

## Arguments

An argument proves membership in one relation:

```text
R subset X x W

public instance: x
private witness: w
verifier output: accept/reject
```

The shared public shape lives on `ArgumentCore`:

```rust,ignore
type Instance = X;
```

Only the prover extends that shape with `ArgumentProverCore`:

```rust,ignore
type Witness = W;
```

Schnorr uses `Instance = (G, X)` and `Witness = x` for the relation
`X = x * G`.

## Reductions

A reduction transforms one claim into another:

```text
source relation: R0
target relation: R1

prover input:    x0, w0
prover output:   x1, w1
verifier input:  x0
verifier output: x1
```

`ReductionCore` contains only the public shape:

```rust,ignore
type SourceInstance = X0;
type TargetInstance = X1;
```

`ReductionProverCore` adds the private shape:

```rust,ignore
type SourceWitness = W0;
type TargetWitness = W1;
```

The verifier computes the target instance independently. The target witness is
available only to prover composition.

## Preprocessing

Preprocessing protocols describe indexed relation families:

```text
{ R_i } indexed by static data i
indexer.preprocess(i) -> (pk_i, vk_i)
```

The independent `Indexer` owns:

```rust,ignore
type Index = I;
type ProverKey = PK;
type VerifierKey = VK;
```

Each executable role owns only the key it consumes. Both key types implement
`CommittedIndex`, allowing backends to bind the same indexed relation before the
first challenge. The indexer must return keys with identical committed-index
bytes; this is an authoring contract rather than a runtime check.

## Interactive and Non-Interactive Roles

Authors implement interactive roles. A backend produces corresponding
non-interactive roles.

Plain argument:

```rust,ignore
let prover = dsfs::plain_non_interactive_argument_prover(
    argument_prover,
    dsfs::Keccak::default(),
);
let verifier = dsfs::plain_non_interactive_argument_verifier(
    argument_verifier,
    dsfs::Keccak::default(),
);

let proof = prover.prove(&session, &instance, &witness);
verifier.verify(&session, &instance, &proof)?;
```

Preprocessing argument:

```rust,ignore
let (pk, vk) = indexer.preprocess(&index);

let prover = dsfs::preprocessing_non_interactive_argument_prover(
    argument_prover,
    dsfs::Keccak::default(),
);
let verifier = dsfs::preprocessing_non_interactive_argument_verifier(
    argument_verifier,
    dsfs::Keccak::default(),
);

let proof = prover.prove(&pk, &session, &instance, &witness);
verifier.verify(&vk, &session, &instance, &proof)?;
```

The compiled objects store neither keys nor an opposite executable role.

## Security Ownership

Plain security metadata lives on verifier types because it describes the
verification algorithm and public statement:

- `ArgumentSecurity`
- `ReductionSecurity`

Preprocessing security metadata lives on indexer types because its bounds may
depend on static index parameters:

- `PreprocessingArgumentSecurity`
- `PreprocessingReductionSecurity`
