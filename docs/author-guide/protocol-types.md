# Protocol Types

Argus protocols are easiest to classify by verifier output and setup shape.

## Arguments

An argument proves membership in one relation:

```text
R subset X x W

public instance: x
private witness: w
claim:           (x, w) in R
verifier output: accept/reject
```

In Rust:

```rust
type Instance = X;
type Witness = W;
```

Schnorr is the smallest example:

```text
R_schnorr = { ((G, X), x) : X = x * G }

Instance = (G, X)
Witness  = x
```

## Reductions

A reduction proves that one claim can be transformed into another claim:

```text
source relation: R0
target relation: R1

prover input:    x0, w0
prover output:   x1, w1
verifier input:  x0
verifier output: x1
```

In Rust:

```rust
type SourceInstance = X0;
type SourceWitness = W0;
type TargetInstance = X1;
type TargetWitness = W1;
```

The prover returns both the target instance and target witness because it may
feed them into the next prover step. The verifier returns only the target
instance because it must compute the next public claim without trusting the
prover's copy.

Use reductions for folding, accumulation, and protocols where "verification"
means producing the next statement rather than deciding the final statement.

## Preprocessing

Preprocessing protocols describe indexed relation families:

```text
{ R_i } indexed by static data i
preprocess(i) -> (pk_i, vk_i)
```

The index is setup data. The ordinary instance is still per claim.

```text
prover input:    pk_i, x, w
verifier input:  vk_i, x
verifier output: accept/reject or target instance
```

In Rust:

```rust
type Index = I;
type ProverKey = PK;
type VerifierKey = VK;
```

Both keys implement `CommittedIndex`, allowing the backend to bind the indexed
relation before the first challenge. For asymmetric protocols, the prover key
may be large while the verifier key is compact.

## Interactive and Non-Interactive

Authors normally implement the interactive shape. A backend provides the
non-interactive view.

Plain argument:

```rust
let nia = dsfs::plain_non_interactive_argument(body, dsfs::Keccak::default());
let proof = nia.prove(&session, &instance, &witness);
nia.verify(&session, &instance, &proof)?;
```

Preprocessing argument:

```rust
let pnia = dsfs::preprocessing_non_interactive_argument(body, dsfs::Keccak::default());
let (pk, vk) = pnia.preprocess(&index);
let proof = pnia.prove(&pk, &session, &instance, &witness);
pnia.verify(&vk, &session, &instance, &proof)?;
```

The preprocessing wrapper stores no keys. Keys are inputs to proving and
verification.

## Prover and Verifier Roles

Each leaf trait above splits into a `…Prover` half and a `…Verifier` half, with
the full trait as their conjunction. You still author one block with both methods
(the macro emits the halves), but a *compiled* object can hold a single role:

```rust
use ia_core::prelude::*;   // .prove()/.verify() live on the halves

let prover = dsfs::plain_non_interactive_argument(body.into_prover(), dsfs::Keccak::default());
// prover.prove(...)  — yes;  prover.verify(...)  — does not exist
```

`into_prover()` / `into_verifier()` are API-level role views over a full body; a
natively one-sided body (implementing only `…Verifier`) drops the other algorithm
entirely. See [Prover/Verifier Split](../prover-verifier-split-presentation.md).
