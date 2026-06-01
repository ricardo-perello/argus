# WARP: Linear-Time Accumulation Scheme

## What is WARP

WARP is a linear-time accumulation scheme for R1CS from [eprint 2025/753](https://eprint.iacr.org/2025/753). Given `l` R1CS instances (some fresh, some previously accumulated), WARP produces a single accumulated instance and witness. The verifier checks consistency of the reduction; the decider checks that the accumulated witness actually satisfies the accumulated instance.

The protocol is an Interactive Oracle Reduction (IOR): the verifier does not
output accept/reject, but a new reduced instance. In Argus this is modeled as a
preprocessing reduction: the static WARP problem description is preprocessed
into prover/verifier keys, while per-claim public inputs stay in the ordinary
instance.

## Crate structure

```
crates/warp/
  src/
    lib.rs              -- module declarations, re-exports (FullWarp, WarpReduction, WarpDecider)
    config.rs           -- WarpConfig (l, l1, s, t, etc.)
    errors.rs           -- WARPError, WARPProverError, WARPVerifierError, WARPDeciderError
    types.rs            -- all intermediate instance/witness types
    protocol/
      mod.rs            -- sub-module declarations
      warp.rs           -- indexed material, keys, instance/witness encoding, protocol engine
      ir.rs             -- WarpReduction (IR), WarpDecider (IA), FullWarp single-index IA
      twin_sumcheck.rs  -- twin constraint pseudo-batching sumcheck (prover + verifier)
      batching_sumcheck.rs -- inner product sumcheck / CBBZ23 (prover + verifier)
    relations/
      mod.rs            -- Relation, BundledPESAT, ToPolySystem traits
      description.rs    -- SerializableConstraintMatrices
      r1cs/
        mod.rs          -- R1CS struct, R1CSConstraints, BundledPESAT impl
        hashchain/      -- concrete hash-chain relation (for testing)
    crypto/
      mod.rs
      merkle/
        mod.rs          -- build_codeword_leaves, compute_auth_paths
        parameters.rs   -- generic MerkleTreeParams
        blake3.rs       -- Blake3MerkleConfig, Blake3MerkleTreeParams
    utils/
      mod.rs            -- field utilities, FastMap, BoolResult
      poly.rs           -- eq_poly, Hypercube, tablewise_reduce, pairwise_reduce
      poseidon.rs       -- Poseidon config for hash-chain test relation
  tests/
    warp_test.rs        -- end-to-end integration tests
```

## Protocol overview

WARP preprocessing takes as input:

- An R1CS constraint system `P` and a Reed-Solomon code `C`
- WARP configuration and dimensions

Each claim then takes:

- `l1` fresh R1CS instances and witnesses
- `l2 = l - l1` previously accumulated instances and witnesses from prior WARP runs

The protocol has five phases, implemented by an internal `WarpStaticMaterial`
engine derived from `WarpIndex` during preprocessing:

### Phase 1: Parse and Commit

The prover Reed-Solomon encodes each witness into a codeword, builds a Merkle tree over the codewords, and sends the root. It then sends `mu_i = codeword_i[0]` for each instance. The verifier squeezes random `tau` vectors (one per instance) for the circuit evaluation point.

### Phase 2: Constrained Code Accumulation (Twin Sumcheck)

The prover and verifier run a twin constraint pseudo-batching sumcheck over `log_l` rounds. This folds all `l` evaluation tables (codewords, witnesses, R1CS circuit evaluations, tau vectors) into a single instance. The "twin" refers to the two constraint sources being folded simultaneously:

- **f**: the code constraint (Reed-Solomon evaluation vs. committed codeword)
- **p**: the PESAT constraint (R1CS A*B - C)

Each round, the prover computes a polynomial `h` using the ProtoGalaxy trick, sends its coefficients (zero-padded to a fixed count), and receives a folding challenge.

### Phase 3: Commit and Sample

The prover builds a new Merkle tree over the folded codeword, sends the root, eta, and nu_0. The verifier squeezes out-of-domain (OOD) sample points and shift query positions. The prover evaluates the folded codeword at the OOD points and sends the answers.

### Phase 4: Batching Sumcheck (Inner Product)

The prover and verifier run an inner product sumcheck (CBBZ23 optimization) over `log_n` rounds. This reduces the check that `f` and a batched constraint polynomial `g` have the correct inner product to a single-point evaluation. Each round sends three scalars (sum_00, sum_11, sum_0110) and receives one challenge.

### Phase 5: Decision

The decider (local check, no channel interaction) verifies that the accumulated witness satisfies the accumulated instance:

- Code evaluation point consistency
- Circuit evaluation point consistency
- Merkle opening proofs for the initial and folded commitments
- Shift query answer consistency
- Accumulated mu and eta consistency

## How it connects to Argus

### Channel abstraction

All channel operations go through `ia_core::ProverChannel` / `ia_core::VerifierChannel`. The prover absorbs instances and sends proof elements via `ch.send_prover_message()`. The verifier reads them via `ch.read_prover_message()`. Challenges are squeezed via `ch.read_verifier_message()` (prover) and `ch.send_verifier_message()` (verifier). The WARP code never touches a sponge directly.

### IR/IA composition

WARP is expressed as two composable preprocessing components using the `ia-core`
traits:

- **`WarpReduction`** (`PreprocessingInteractiveReduction`): The full IOR -- runs
  all five phases of the protocol (parse/commit, twin sumcheck, commit/sample,
  batching sumcheck) and produces a target `AccumulatorInstances`. The prover
  receives `WarpProverKey`; the verifier receives `WarpVerifierKey`.
  `WarpVerifierKey::committed_index()` binds a compact digest of the static
  verifier-side material -- dimensions, WARP configuration, code parameters,
  Merkle hash parameters, and R1CS constraint matrices -- before DSFS derives
  any challenges.

- **`WarpDecider`** (`PreprocessingInteractiveArgument`): The decider as a
  preprocessing IA -- the prover sends the accumulated codeword and witness through
  the channel; the verifier reads them back, reconstructs the Merkle tree, and
  checks code consistency, PESAT evaluation, and encoding correctness.

The full argument is a first-class preprocessing IA:

```rust
struct FullWarp<F, P, C, MT> { /* WarpReduction + WarpDecider */ }
```

Unlike the generic composition adapter, `FullWarp` has a single
`Index = WarpIndex<...>`. The reduction and decider share one verifier key and
one verifier-key commitment:

```rust
let warp_index = WarpIndex::new(
    WarpConfig::new(l, l1, s, t, r1cs.config(), code.code_len()),
    r1cs,
    code,
    WarpMerkleParams::new(leaf_hash_params, two_to_one_hash_params),
);

let full = FullWarp::<Fp, R1CS<Fp>, RS, MT>::default();
let narg = spongefish_dsfs::preprocessing_non_interactive_argument(
    full,
    spongefish_dsfs::Keccak::default(),
);
let (pk, vk) = narg.preprocess(&warp_index);

let proof = narg.prove(&pk, &session, &instance, &witness);
narg.verify(&vk, &session, &instance, &proof)?;
```

The reduction can also be used standalone for IOR-level verification:

```rust
let reduction = WarpReduction::<Fp, R1CS<Fp>, RS, MT>::new();
let narg = spongefish_dsfs::preprocessing_non_interactive_reduction(
    reduction,
    spongefish_dsfs::Keccak::default(),
);
let (pk, vk) = narg.preprocess(&warp_index);

let (proof, target, target_witness) = narg.prove(&pk, &session, &instance, &witness);
let verified_target = narg.verify(&vk, &session, &instance, &proof)?;
// target.acc_instance is the new AccumulatorInstances
```

### Index commitment and instance separation

The old standalone WARP code absorbed static relation material during setup. In
Argus, protocol code cannot touch the transcript, so that setup binding is
represented by `WarpVerifierKey::committed_index()` and
`WarpProverKey::committed_index()`.

`WarpIndex` contains the static relation/config/code/Merkle data. Preprocessing
derives:

- `WarpProverKey`: prover-side static material.
- `WarpVerifierKey`: verifier-side static material plus a derived commitment.

The verifier-key commitment binds dimensions, WARP configuration, code material,
Merkle hash parameters, and the R1CS matrices with explicit tags and
length-delimited fields. `WarpInstance` contains only per-claim instances and
accumulator instances. Preprocessing DSFS absorbs:

```text
IndexedInstanceRef {
    committed_index: vk.committed_index(),
    instance: &WarpInstance,
}
```

before any challenge. Static index material is never smuggled through the
instance just to make the transcript see it.

### Merkle path verification (BCS layer)

Merkle auth-path verification remains separate from the IR/IA composition. The
IR verifier handles transcript-based checks (sumchecks, consistency equations).
The internal protocol engine still contains the oracle-opening checks used by
the full verifier path, matching the IOR/BCS separation where the IOR handles
the interactive protocol and the commitment scheme handles oracle openings.

## Dependencies

| Dependency | Purpose |
|---|---|
| `ia-core` | `ProverChannel`, `VerifierChannel` traits |
| `spongefish::dsfs` | `SpongeProver`, `SpongeVerifier` (test only) |
| `spongefish` | `Encoding`, `Decoding` for field elements |
| `ark-ff`, `ark-poly`, `ark-serialize` | Field arithmetic, polynomials |
| `ark-relations`, `ark-r1cs-std` | R1CS constraint system |
| `ark-crypto-primitives` | Merkle trees, Poseidon CRH |
| `ark-codes` | Reed-Solomon encoding |
| `blake3` | Merkle tree hash function |
| `rayon` | Parallel computation in ProtoGalaxy trick |
| `nohash-hasher` | Fast `HashMap<usize, F>` for sparse evaluations |

The `ark-crypto-primitives` dependency uses a [patched fork](https://github.com/dmpierre/crypto-primitives/tree/dev/blake3) that adds Blake3 support.

## Security profile (PreprocessingReductionSecurity)

`WarpReduction` implements `PreprocessingReductionSecurity` with bounds from eprint 2025/753.
Both the Schwartz-Zippel per-round errors and the code-specific one-time terms
(errPG, OOD sampling, shift sampling, PESAT→code) are included.

### Construction

`WarpReduction::new()` carries no duplicated security fields. The instance-aware
security API derives `WarpSecurityParams` from the source `WarpInstance`:

```rust
let ir = WarpReduction::new();
let ix_params = ir.index_security_params(&warp_index);
let profile = ir.profile_for_source_params(&ix_params, &());
```

The derived parameters include `log_l`, `log_n`, `log_m`, Reed-Solomon code
parameters, `WarpConfig.s`, and `WarpConfig.t`. Worst-case/adaptive evaluation
uses the same `WarpSecurityBound` shape, interpreted as maxima over the instance
family.

### Round structure

`log_l + log_n` interactive rounds:

| Rounds | Phase | Protocol |
|---|---|---|
| `log_l` | Twin sumcheck | ProtoGalaxy-style folding |
| `log_n` | Batching sumcheck | CBBZ23 inner product |

### Per-round RBR bounds (rbr_soundness_errors)

**Twin sumcheck** (§6.1–6.2): round j (0-indexed), degree `twin_deg = 1 + max(log_n+1, log_m+2)`:
```
ε_j^rbr = twin_deg / |F|  +  (ℓ / 2^j) · err_PG(C, 2, δ)
```
The errPG term shrinks geometrically across rounds: the first round folds all ℓ
instances, so the contribution is largest there.

**Batching sumcheck** (§8): degree 2, all rounds identical:
```
ε_i^rbr = 2 / |F|
```

### One-time commitment-phase terms (plain_soundness_error)

These terms arise from the commitment and OOD/shift-sampling phases (§5.2, §7).
They do not correspond to interactive sumcheck rounds and do not participate in
the SR adversary budget; they are placed in `plain_soundness_error`:

```
|Λ(C,δ)|² · log_n / |F|   (OOD commitment, §7)
(1 − δ)^shift_queries      (shift-sampling proximity check, §7)
|Λ(C,δ)| · log_m / |F|    (PESAT→code reduction, §5.2)
```

`WarpSecurityParams` carries the raw Reed-Solomon parameters (`n`, `k`, `field_bits`); `warp_security_profile` derives the bounds inline:
- δ = 1 − k/n
- |Λ(C, δ)| ≤ n  (conservative; TODO: tighten via Johnson bound)
- err_PG(C, 2, δ) ≤ 3 · n² / |F|  (BCIKS20 bound, degree 2)

### Placement of commitment terms (open Q for Chiesa)

Whether the OOD/shift/PESAT terms should be in `plain_soundness_error` or
`rbr_soundness_errors` depends on whether the SR adversary can rewind through
the commitment phase. The current placement (non-SR) matches the intuition that
these are binding-style terms, not per-round protocol moves. Pending Chiesa Q2.

`WarpDecider` has no public-coin rounds (deterministic local check) -- all its
error bounds are zero.

---

## Differences from the original `~/Developer/warp`

The original warp codebase uses spongefish directly (`ProverState` / `VerifierState`) and defines its own `WARPDomainSeparator` that builds a precise absorb/squeeze pattern upfront. The Argus port replaces all spongefish calls with channel trait calls, deferring the sponge management to whichever channel backend is plugged in.

The `efficient-sumcheck` dependency from the original code was removed entirely. Its small set of needed utilities (`Hypercube` iterator, `eq_poly`, `pairwise_reduce`, `tablewise_reduce`) were reimplemented in `utils/poly.rs` to avoid pulling in a newer spongefish revision that would have broken the rest of the Argus workspace.

## Tests

Eleven integration tests in `tests/warp_test.rs`:

- `warp_security_profile_is_derived_from_index` -- checks that WARP security parameters are derived from the static index rather than the per-claim instance.
- `warp_commitment_stable_for_same_index` -- checks deterministic verifier-key commitments.
- `warp_commitment_changes_when_constraints_change` -- keeps dimensions fixed while changing one R1CS coefficient and checks that the verifier-key commitment changes.
- `warp_commitment_changes_when_code_changes` -- checks that code material is part of the verifier-key commitment.
- `warp_commitment_changes_when_config_changes` -- checks that WARP config changes are bound.
- `warp_commitment_changes_when_merkle_params_change` -- checks that Merkle hash parameters are bound.
- `proof_rejects_with_wrong_verifier_key_same_dimensions` -- proves under one static relation and verifies under another relation with the same dimensions; verification rejects.
- `warp_instance_encoding_excludes_static_index_material` -- checks that the instance encoding stays per-claim and does not carry static index data.
- `warp_ir_dsfs_prove_verify` -- uses `preprocessing_non_interactive_reduction(...).preprocess(&ix)` with `WarpReduction`, then passes `pk`/`vk` as inputs.
- `full_warp_uses_single_index` -- compile-time check that `FullWarp::Index = WarpIndex`, not `(WarpIndex, WarpIndex)`.
- `full_warp_dsfs_roundtrip` -- uses `preprocessing_non_interactive_argument(...).preprocess(&ix)` with `FullWarp`, then passes `pk`/`vk` as inputs.

All tests use the BLS12-381 scalar field with a Poseidon hash-chain R1CS relation, Reed-Solomon encoding, and Blake3 Merkle trees.

## Cross-crate boundary

WARP v2 does not change DSFS transcript ordering. It relies on the existing
preprocessing DSFS path: `preprocessing_non_interactive_argument(...)` and
`preprocessing_non_interactive_reduction(...)` derive committed-index bytes from
the supplied key and absorb those bytes plus the encoded `WarpInstance` before
the first challenge.
