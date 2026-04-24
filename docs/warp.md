# WARP: Linear-Time Accumulation Scheme

## What is WARP

WARP is a linear-time accumulation scheme for R1CS from [eprint 2025/753](https://eprint.iacr.org/2025/753). Given `l` R1CS instances (some fresh, some previously accumulated), WARP produces a single accumulated instance and witness. The verifier checks consistency of the reduction; the decider checks that the accumulated witness actually satisfies the accumulated instance.

The protocol is an Interactive Oracle Reduction (IOR): the verifier does not output accept/reject, but a new (reduced) instance. This maps directly onto Argus's `InteractiveReduction` interface.

## Crate structure

```
crates/warp/
  src/
    lib.rs              -- module declarations, re-exports (FullWARP, WARPReduction, WARPDeciderIA, ReedSolomonParams)
    config.rs           -- WARPConfig (l, l1, s, t, etc.)
    errors.rs           -- WARPError, WARPProverError, WARPVerifierError, WARPDeciderError
    rs_params.rs        -- ReedSolomonParams, CodeSecurityParams impl (orphan-rule-safe newtype)
    types.rs            -- all intermediate instance/witness types
    protocol/
      mod.rs            -- sub-module declarations
      warp.rs           -- WARP struct, prove/verify/decide, Encoding, DeciderInstance
      ir.rs             -- WARPReduction (IR), WARPDeciderIA (IA), FullWARP type alias
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

WARP takes as input:

- `l1` fresh R1CS instances and witnesses
- `l2 = l - l1` previously accumulated instances and witnesses (from prior WARP runs)
- An R1CS constraint system `P` and a Reed-Solomon code `C`

The protocol has five phases, all implemented inside a single `WARP` struct:

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

WARP is expressed as two composable components using the `ia-core` traits:

- **`WARPReduction`** (`InteractiveReduction`): The full IOR -- runs all five phases of the protocol (parse/commit, twin sumcheck, commit/sample, batching sumcheck) and produces a target `AccumulatorInstances`. The verifier computes the target from the transcript rather than checking a provided answer.

- **`WARPDeciderIA`** (`InteractiveArgument`): The decider as an IA -- the prover sends the accumulated codeword and witness through the channel; the verifier reads them back, reconstructs the Merkle tree, and checks code consistency, PESAT evaluation, and encoding correctness.

These are composed via `ReducedArgument` (IR . IA -> IA):

```rust
type FullWARP<F, P, C, MT> = ReducedArgument<WARPReduction<F, P, C, MT>, WARPDeciderIA<F, P, C, MT>>;
```

This gives a single `InteractiveArgument` that can be compiled through DSFS in one call:

```rust
let proof = spongefish::dsfs::prove::<FullWARP<Fp, R1CS<Fp>, RS, MT>>(session, &instance, &witness);
spongefish::dsfs::verify::<FullWARP<Fp, R1CS<Fp>, RS, MT>>(session, &instance, proof.as_bytes())?;
```

The reduction can also be used standalone for IOR-level verification:

```rust
let proof = spongefish::dsfs::prove_reduction::<WARPReduction<...>>(session, &instance, &witness);
let target = spongefish::dsfs::verify_reduction::<WARPReduction<...>>(session, &instance, proof.as_bytes())?;
// target.acc_instance is the new AccumulatorInstances
```

### Merkle path verification (BCS layer)

Merkle auth-path verification is separate from the IR/IA composition. The IR verifier handles only transcript-based checks (sumchecks, consistency equations). Oracle opening proofs are verified by `WARP::verify_merkle_paths`, matching the IOR/BCS separation where the IOR handles the interactive protocol and the commitment scheme handles oracle openings.

### Low-level API

The `WARP` struct still exposes `prove_with_channel`, `verify_with_channel`, and `decide` for direct use:

```rust
impl WARP<F, P, C, MT> {
    pub fn prove_with_channel<Ch: ProverChannel>(...) -> Result<(AccumulatorInstances, AccumulatorWitnesses, WARPProofData), ...>;
    pub fn verify_reduction_transcript<Ch: VerifierChannel>(...) -> Result<ReductionTranscriptResult, ...>;
    pub fn verify_merkle_paths(...) -> Result<(), ...>;
    pub fn verify_with_channel<Ch: VerifierChannel>(...) -> Result<(), ...>;
    pub fn decide(...) -> Result<(), ...>;
}
```

## Dependencies

| Dependency | Purpose |
|---|---|
| `ia-core` | `ProverChannel`, `VerifierChannel` traits |
| `dsfs` | `SpongeProver`, `SpongeVerifier` (test only) |
| `spongefish` | `Encoding`, `Decoding` for field elements |
| `ark-ff`, `ark-poly`, `ark-serialize` | Field arithmetic, polynomials |
| `ark-relations`, `ark-r1cs-std` | R1CS constraint system |
| `ark-crypto-primitives` | Merkle trees, Poseidon CRH |
| `ark-codes` | Reed-Solomon encoding |
| `blake3` | Merkle tree hash function |
| `rayon` | Parallel computation in ProtoGalaxy trick |
| `nohash-hasher` | Fast `HashMap<usize, F>` for sparse evaluations |

The `ark-crypto-primitives` dependency uses a [patched fork](https://github.com/dmpierre/crypto-primitives/tree/dev/blake3) that adds Blake3 support.

## Security profile (ProtocolSecurity)

`WARPReduction` implements `ProtocolSecurity` with bounds from eprint 2025/753.
Both the Schwartz–Zippel per-round errors and the code-specific one-time terms
(errPG, OOD sampling, shift sampling, PESAT→code) are included.

### Construction

`WARPReduction::new(log_l, log_n, log_m, code_params, ood_samples, shift_queries)`
where `code_params` is a `ReedSolomonParams` holding `(n, k, field_size_bits)`:

```rust
let code_params = ReedSolomonParams::new(
    code.code_len(),    // n
    code.message_len(), // k
    F::MODULUS_BIT_SIZE,
);
let ir = WARPReduction::new(log_l, log_n, log_m, code_params, s, t);
// s = WARPConfig.s (OOD samples), t = WARPConfig.t (shift queries)
```

`Default` is not implemented — callers must supply explicit code parameters.

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

`ReedSolomonParams` provides these via `CodeSecurityParams` (trait from `ia-core`):
- `distance()` = 1 − k/n
- `list_size_bound()` = n (conservative; TODO: tighten via Johnson bound)
- `proximity_generator_error(d)` = (d+1) · n² / |F|  (BCIKS20 bound)

### Placement of commitment terms (open Q for Chiesa)

Whether the OOD/shift/PESAT terms should be in `plain_soundness_error` or
`rbr_soundness_errors` depends on whether the SR adversary can rewind through
the commitment phase. The current placement (non-SR) matches the intuition that
these are binding-style terms, not per-round protocol moves. Pending Chiesa Q2.

`WARPDeciderIA` has no public-coin rounds (deterministic local check) — all its
error bounds are zero.

---

## Differences from the original `~/Developer/warp`

The original warp codebase uses spongefish directly (`ProverState` / `VerifierState`) and defines its own `WARPDomainSeparator` that builds a precise absorb/squeeze pattern upfront. The Argus port replaces all spongefish calls with channel trait calls, deferring the sponge management to whichever channel backend is plugged in.

The `efficient-sumcheck` dependency from the original code was removed entirely. Its small set of needed utilities (`Hypercube` iterator, `eq_poly`, `pairwise_reduce`, `tablewise_reduce`) were reimplemented in `utils/poly.rs` to avoid pulling in a newer spongefish revision that would have broken the rest of the Argus workspace.

## Tests

Four integration tests in `tests/warp_test.rs`:

- `warp_bootstrap_prove_verify_decide` -- single proof with empty accumulator (l1=4 fresh instances, l2=0 accumulated). Proves, verifies via NARG string replay, runs decider.
- `warp_full_accumulation_cycle` -- runs 4 bootstrap proofs to build up accumulated state, then a full proof with l1=4 fresh + l2=4 accumulated instances (l=8). Proves, verifies, decides.
- `warp_ir_dsfs_prove_verify` -- uses `spongefish::dsfs::prove_reduction` / `spongefish::dsfs::verify_reduction` with `WARPReduction`. Validates that the IR interface works end-to-end through DSFS.
- `warp_full_ia_dsfs_prove_verify` -- uses `spongefish::dsfs::prove` / `spongefish::dsfs::verify` with `FullWARP` (= `ReducedArgument<WARPReduction, WARPDeciderIA>`). Validates the full composed IA through DSFS.

All tests use the BLS12-381 scalar field with a Poseidon hash-chain R1CS relation, Reed-Solomon encoding, and Blake3 Merkle trees.

## Files changed outside `crates/warp/`

- [Cargo.toml](../Cargo.toml) -- added `crates/warp` to workspace members, added `ark-relations`, `ark-r1cs-std`, `ark-crypto-primitives`, `ark-codes`, `thiserror`, `rayon`, `blake3` to workspace deps, added `[patch.crates-io]` for Blake3-enabled `ark-crypto-primitives`
- `spongefish::dsfs` -- provides `SpongeProver::new()`, `SpongeProver::narg_string()`, `SpongeVerifier::new()` constructors so test code can create sponge channels directly
