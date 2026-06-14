# `spongefish-dsfs`

`spongefish-dsfs` compiles each interactive role independently while owning all
transcript mechanics.

## Plain Arguments

```rust,ignore
let prover = spongefish_dsfs::argument_prover(
    prover_body,   // your `InteractiveArgumentProver`
    spongefish_dsfs::Keccak::default(),
);
let verifier = spongefish_dsfs::argument_verifier(
    verifier_body, // your `InteractiveArgumentVerifier`
    spongefish_dsfs::Keccak::default(),
);

let proof = prover.prove(&session, &instance, &witness);
verifier.verify(&session, &instance, &proof)?;
```

Reductions use `reduction_prover` and
`reduction_verifier`. Salted variants append
`_with_salt` to the role-specific constructor name.

## Preprocessing

Indexing remains outside DSFS:

```rust,ignore
let (pk, vk) = indexer.preprocess(&index);

let prover = spongefish_dsfs::preprocessing::argument_prover(
    prover_body,   // your `PreprocessingInteractiveArgumentProver`
    spongefish_dsfs::Keccak::default(),
);
let verifier = spongefish_dsfs::preprocessing::argument_verifier(
    verifier_body, // your `PreprocessingInteractiveArgumentVerifier`
    spongefish_dsfs::Keccak::default(),
);

let proof = prover.prove(&pk, &session, &instance, &witness);
verifier.verify(&vk, &session, &instance, &proof)?;
```

The prover wrapper names only `ProverKey`; the verifier wrapper names only
`VerifierKey`. DSFS derives the committed index from the supplied key and binds
it with the public instance before the first challenge.

Preprocessing reductions use the corresponding
`preprocessing::reduction_prover` and
`preprocessing::reduction_verifier` constructors.

## Compiled Types

The module path marks the axis; the leaf name marks the role. (`NonInteractive`
is implied — the DSFS compiler only produces non-interactive roles.)

Plain (crate root):

- `ArgumentProver` / `ArgumentVerifier`
- `ReductionProver` / `ReductionVerifier`

Preprocessing (`preprocessing` module):

- `preprocessing::ArgumentProver` / `preprocessing::ArgumentVerifier`
- `preprocessing::ReductionProver` / `preprocessing::ReductionVerifier`

DSFS does not implement or forward `Indexer`, and it does not provide a combined
compiled object.

## Invariants

DSFS owns:

- public-input and committed-index absorption,
- prefix-free instance framing (tagged, length-prefixed) on both the plain and
  preprocessing paths, so statement binding does not depend on the author's
  `Instance` encoding being prefix-free,
- prover-message absorption before each challenge,
- challenge derivation,
- optional salt handling,
- proof serialization,
- deterministic verifier replay,
- EOF and trailing-byte rejection.

The Argus standard sponge is `Keccak`. `StdHash` remains available for explicit
compatibility paths. Any sponge, salt, proof-layout, or transcript initialization
change requires a protocol-id review.
