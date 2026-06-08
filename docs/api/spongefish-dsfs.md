# `spongefish-dsfs`

`spongefish-dsfs` compiles each interactive role independently while owning all
transcript mechanics.

## Plain Arguments

```rust
let prover = spongefish_dsfs::plain_non_interactive_argument_prover(
    argument_prover,
    spongefish_dsfs::Keccak::default(),
);
let verifier = spongefish_dsfs::plain_non_interactive_argument_verifier(
    argument_verifier,
    spongefish_dsfs::Keccak::default(),
);

let proof = prover.prove(&session, &instance, &witness);
verifier.verify(&session, &instance, &proof)?;
```

Reductions use `plain_non_interactive_reduction_prover` and
`plain_non_interactive_reduction_verifier`. Salted variants append
`_with_salt` to the role-specific constructor name.

## Preprocessing

Indexing remains outside DSFS:

```rust
let (pk, vk) = indexer.preprocess_checked(&index)?;

let prover = spongefish_dsfs::preprocessing_non_interactive_argument_prover(
    argument_prover,
    spongefish_dsfs::Keccak::default(),
);
let verifier = spongefish_dsfs::preprocessing_non_interactive_argument_verifier(
    argument_verifier,
    spongefish_dsfs::Keccak::default(),
);

let proof = prover.prove(&pk, &session, &instance, &witness);
verifier.verify(&vk, &session, &instance, &proof)?;
```

The prover wrapper names only `ProverKey`; the verifier wrapper names only
`VerifierKey`. DSFS derives the committed index from the supplied key and binds
it with the public instance before the first challenge.

Preprocessing reductions use the corresponding
`preprocessing_non_interactive_reduction_prover` and
`preprocessing_non_interactive_reduction_verifier` constructors.

## Compiled Types

- `DsfsArgumentProver` / `DsfsArgumentVerifier`
- `DsfsReductionProver` / `DsfsReductionVerifier`
- `PreprocessedDsfsArgumentProver` / `PreprocessedDsfsArgumentVerifier`
- `PreprocessedDsfsReductionProver` / `PreprocessedDsfsReductionVerifier`

DSFS does not implement or forward `Indexer`, and it does not provide a combined
compiled object.

## Invariants

DSFS owns:

- public-input and committed-index absorption,
- prover-message absorption before each challenge,
- challenge derivation,
- optional salt handling,
- proof serialization,
- deterministic verifier replay,
- EOF and trailing-byte rejection.

The Argus standard sponge is `Keccak`. `StdHash` remains available for explicit
compatibility paths. Any sponge, salt, proof-layout, or transcript initialization
change requires a protocol-id review.
