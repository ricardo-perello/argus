# WARP

WARP is the largest protocol case study in the workspace.

It is an accumulation scheme for R1CS from ePrint 2025/753. In Argus it is
represented as preprocessing reductions plus a final preprocessing argument.
That is exactly the distinction Argus is meant to make visible: most of WARP
transforms claims, and the final step decides the accumulated claim.

## Shape

WARP setup contains static relation data:

- R1CS description,
- Reed-Solomon code parameters,
- WARP configuration,
- Merkle hash parameters.

That setup is represented as `WarpIndex`. Preprocessing derives:

- `WarpProverKey`: prover-side static material,
- `WarpVerifierKey`: verifier-side material and committed-index bytes.

Each proof then uses a `WarpInstance` and `WarpWitness` for the per-claim data.
Static index material is not smuggled through the ordinary instance just to make
the transcript see it.

## Components

The protocol is exposed through three main components:

```text
WarpReduction : PreprocessingInteractiveReduction
  source claims -> accumulated claim

WarpDecider : PreprocessingInteractiveArgument
  accumulated claim -> accept/reject

FullWarp : PreprocessingInteractiveArgument
  WarpReduction followed by WarpDecider
```

`WarpReduction` can be compiled as a non-interactive reduction when the caller
wants the accumulated target instance. `FullWarp` can be compiled as a
non-interactive argument when the caller wants an end-to-end proof.

## DSFS Use

Full argument:

```rust
let full = FullWarp::<Fp, R1CS<Fp>, RS, MT>::default();
let narg = spongefish_dsfs::preprocessing_non_interactive_argument(
    full,
    spongefish_dsfs::Keccak::default(),
);

let (pk, vk) = narg.preprocess(&warp_index);
let proof = narg.prove(&pk, &session, &instance, &witness);
narg.verify(&vk, &session, &instance, &proof)?;
```

Reduction-only path:

```rust
let reduction = WarpReduction::<Fp, R1CS<Fp>, RS, MT>::new();
let narg = spongefish_dsfs::preprocessing_non_interactive_reduction(
    reduction,
    spongefish_dsfs::Keccak::default(),
);

let (pk, vk) = narg.preprocess(&warp_index);
let (proof, target, target_witness) =
    narg.prove(&pk, &session, &instance, &witness);
let verified_target = narg.verify(&vk, &session, &instance, &proof)?;
```

## Transcript Binding

`WarpVerifierKey::committed_index()` binds the static verifier-side material:
dimensions, WARP configuration, code parameters, Merkle parameters, and R1CS
matrices. The prover key derives the same committed-index bytes from prover-side
material.

Preprocessing DSFS absorbs:

```text
IndexedInstanceRef {
    committed_index,
    instance,
}
```

before any challenge. The WARP protocol code itself only uses channel calls.

## Implementation Caveat

WARP is naturally an IOP/BCS-style protocol: the prover commits to codewords,
the verifier samples query positions, and the prover opens those oracle
positions with authentication paths. The current Argus workspace does not yet
have the IOP-to-IA/iBCS compiler layer that would turn those oracle interactions
into an IA in a principled way.

Because of that, the WARP port has some ad hoc oracle-opening handling. Merkle
roots, query answers, and opening-related data are represented through ordinary
channel messages, while the conceptual BCS oracle layer is still protocol-local.
This is useful as a case study, but it is not the clean final shape for
WARP-like protocols.

The main architectural lesson is that IA/IR is enough to express the reduction
and decider structure, but WARP-like protocols should eventually be produced by
an iBCS/BCS layer that owns oracle commitments and openings.

## Security Metadata

`WarpReduction` implements preprocessing reduction security metadata. Its bounds
are index-aware because code parameters, matrix dimensions, OOD sample counts,
and shift-query counts come from setup rather than from the per-claim instance.

The detailed WARP implementation note, including phase breakdown, dependency
map, tests, and open security-bound questions, is archived at
[WARP Implementation Notes](../history/protocols/warp-implementation-notes.md).
