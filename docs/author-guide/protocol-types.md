# Relations and Protocol Shapes

Argus is easiest to understand from the relation first, and the Rust trait
second.

An ordinary relation is a set:

```text
R ⊆ X × W
```

where:

- `x ∈ X` is the public instance,
- `w ∈ W` is the private witness,
- `(x, w) ∈ R` means the witness proves the statement.

The language decided by the relation is:

```text
L_R = { x ∈ X : ∃ w ∈ W such that (x, w) ∈ R }.
```

The four main Argus authoring traits are different ways of exposing this same
idea.

| Mathematical object | Author trait | Backend result | Verifier output |
| --- | --- | --- | --- |
| `R ⊆ X × W` | `InteractiveArgument` | `NonInteractiveArgument` | accept/reject |
| `R_src → R_tgt` | `InteractiveReduction` | `NonInteractiveReduction` | target instance |
| family `{R_i}` with setup | `PreprocessingInteractiveArgument` | `PreprocessingNonInteractiveArgument` | accept/reject |
| family `{R_i}` with setup and target relation | `PreprocessingInteractiveReduction` | `PreprocessingNonInteractiveReduction` | target instance |

The interactive traits are what authors usually implement. The
non-interactive traits are usually produced by a backend such as DSFS.

## Arguments

An argument proves membership in one relation:

```text
Relation: R ⊆ X × W

Public input to verifier: x ∈ X
Private input to prover:  w ∈ W
Claim:                    (x, w) ∈ R
Verifier output:          accept or reject
```

In Rust:

```rust
type Instance = X;
type Witness = W;
```

The prover receives `(x, w)`. The verifier receives only `x`.

For Schnorr:

```text
R_schnorr = { ((G, X), x) : X = x · G }

Instance = (G, X)
Witness  = x
```

The protocol convinces the verifier that `(G, X)` is in `L_R`, without revealing
`x`.

## Reductions

A reduction proves that a source claim can be transformed into a target claim.
Instead of ending with accept/reject, the verifier computes the target instance.

```text
Source relation: R0 ⊆ X0 × W0
Target relation: R1 ⊆ X1 × W1

Public input to verifier: x0 ∈ X0
Private input to prover:  w0 ∈ W0

Prover output:            (x1, w1)
Verifier output:          x1

Completeness goal:
if (x0, w0) ∈ R0, then the honest prover produces (x1, w1) ∈ R1,
and the verifier outputs the same x1.
```

In Rust:

```rust
type SourceInstance = X0;
type SourceWitness = W0;
type TargetInstance = X1;
type TargetWitness = W1;
```

The prover returns the target instance and target witness so another protocol
can continue from there. The verifier returns the target instance because it
must be able to feed the next verifier step without trusting the prover's copy.

This is the shape used by folding, accumulation, and WARP.

## Indexed Relations

Preprocessing protocols are about relation families.

Instead of one relation `R`, there is a family:

```text
{ R_i ⊆ X_i × W_i } indexed by i ∈ I
```

The index `i` is static setup data. Preprocessing derives keys:

```text
preprocess(i) -> (pk_i, vk_i)
```

A preprocessing argument proves:

```text
Claim: (x, w) ∈ R_i

Prover input:  pk_i, x, w
Verifier input: vk_i, x
Verifier output: accept or reject
```

In Rust:

```rust
type Index = I;
type ProverKey = PK;
type VerifierKey = VK;
type Instance = X_i;
type Witness = W_i;
```

Both keys implement `CommittedIndex`, which gives the backend a canonical public
byte string for the indexed relation. DSFS binds that committed index together
with the per-claim instance before the first challenge.

Preprocessed Schnorr is a small indexed relation:

```text
i = G
R_G = { (X, x) : X = x · G }

Index    = G
Instance = X
Witness  = x
```

Merkle lookup is a more realistic asymmetric indexed relation:

```text
i = table T
R_T = { ((j, y), ()) : T[j] = y }

Index       = T
ProverKey   = T plus Merkle tree
VerifierKey = Merkle root plus length
Instance    = (j, y)
Witness     = ()
```

## Indexed Reductions

A preprocessing reduction combines both ideas:

```text
indexed source relation: R0_i ⊆ X0_i × W0_i
indexed target relation: R1_i ⊆ X1_i × W1_i

preprocess(i) -> (pk_i, vk_i)

Prover input:  pk_i, x0, w0
Verifier input: vk_i, x0
Prover output:  x1, w1
Verifier output: x1
```

WARP lives here: the static R1CS/code data is the index, each claim is an
ordinary instance, and the reduction outputs an accumulated instance that a
decider can check.

## Non-Interactive Is a Backend View

As an author, start with the interactive shape. DSFS compiles it into the
non-interactive shape:

```rust
let proof = nia.prove(&session, &instance, &witness);
nia.verify(&session, &instance, &proof)?;
```

For preprocessing NARGs, keys remain explicit inputs:

```rust
let (pk, vk) = pnia.preprocess(&index);
let proof = pnia.prove(&pk, &session, &instance, &witness);
pnia.verify(&vk, &session, &instance, &proof)?;
```

This keeps the protocol interface honest: protocol authors describe relations
and conversations; backends decide how to execute them.
