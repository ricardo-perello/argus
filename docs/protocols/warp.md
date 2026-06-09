# WARP

WARP is the largest protocol case study in the workspace. It is an accumulation
scheme for R1CS from ePrint 2025/753, represented as preprocessing reductions
plus a final preprocessing argument.

## Static and Per-Claim Data

`WarpIndex` contains:

- the R1CS description,
- Reed-Solomon parameters,
- WARP configuration,
- Merkle hash parameters.

Indexing derives:

- `WarpProverKey`: prover-side static material,
- `WarpVerifierKey`: verifier-side material and committed-index encoding.

Each proof then uses a `WarpInstance` and `WarpWitness`.

## Role Families

WARP exposes three native role families:

```text
WarpReductionIndexer
WarpReductionProver
WarpReductionVerifier

WarpDeciderIndexer
WarpDeciderProver
WarpDeciderVerifier

FullWarpIndexer
FullWarpProver
FullWarpVerifier
```

The reduction roles transform source claims into an accumulated claim. The
decider roles accept or reject that accumulated claim. The full roles run both
steps as one argument.

`WarpDeciderProverKey` is intentionally lightweight: it carries the same
committed-index value as the decider verifier key without importing all verifier
material into the prover role.

## Full DSFS Argument

```rust,ignore
let indexer = FullWarpIndexer::<Fp, R1CS<Fp>, RS, MT>::default();
let prover = spongefish_dsfs::preprocessing_non_interactive_argument_prover(
    FullWarpProver::<Fp, R1CS<Fp>, RS, MT>::default(),
    spongefish_dsfs::Keccak::default(),
);
let verifier = spongefish_dsfs::preprocessing_non_interactive_argument_verifier(
    FullWarpVerifier::<Fp, R1CS<Fp>, RS, MT>::default(),
    spongefish_dsfs::Keccak::default(),
);

let (pk, vk) = indexer.preprocess(&warp_index);
let proof = prover.prove(&pk, &session, &instance, &witness);
verifier.verify(&vk, &session, &instance, &proof)?;
```

## Reduction-Only Path

```rust,ignore
let indexer = WarpReductionIndexer::<Fp, R1CS<Fp>, RS, MT>::default();
let prover = spongefish_dsfs::preprocessing_non_interactive_reduction_prover(
    WarpReductionProver::<Fp, R1CS<Fp>, RS, MT>::default(),
    spongefish_dsfs::Keccak::default(),
);
let verifier = spongefish_dsfs::preprocessing_non_interactive_reduction_verifier(
    WarpReductionVerifier::<Fp, R1CS<Fp>, RS, MT>::default(),
    spongefish_dsfs::Keccak::default(),
);

let (pk, vk) = indexer.preprocess(&warp_index);
let (proof, target, target_witness) =
    prover.prove(&pk, &session, &instance, &witness);
let verified_target =
    verifier.verify(&vk, &session, &instance, &proof)?;
```

## Single-Index Full Protocol

`FullWarpIndexer` is implemented manually rather than by tuple-composing the
reduction and decider indexers. This preserves WARP's existing commitment bytes,
protocol identifiers, and transcript layout.

## Transcript Binding

Both WARP key types derive the same committed-index bytes from static material:
dimensions, configuration, code parameters, Merkle parameters, and R1CS
matrices. DSFS binds those bytes together with the per-claim instance before the
first challenge. WARP protocol code uses channel calls only.

## Security Metadata

`PreprocessingReductionSecurity` and `PreprocessingArgumentSecurity` are
implemented on the relevant WARP indexer types. This is where index-dependent
parameters such as code dimensions and query counts are available.

## Implementation Caveat

WARP is naturally an IOP/BCS-style protocol. The workspace does not yet contain
the general IOP-to-IA/iBCS layer that would own oracle commitments and openings,
so some opening handling remains protocol-local channel traffic. The IA/IR
decomposition is useful, but an eventual iBCS layer should own that oracle
machinery.

The archived implementation note remains available at
[WARP Implementation Notes](../history/protocols/warp-implementation-notes.md).
