# WARP: Linear-Time Accumulation Scheme

## What is WARP

WARP is a linear-time accumulation scheme for R1CS from [eprint 2025/753](https://eprint.iacr.org/2025/753). Given `l` R1CS instances (some fresh, some previously accumulated), WARP produces a single accumulated instance and witness. The verifier checks consistency of the reduction; the decider checks that the accumulated witness actually satisfies the accumulated instance.

The protocol is an Interactive Oracle Reduction (IOR): the verifier does not output accept/reject, but a new (reduced) instance. This maps directly onto Argus's `InteractiveReduction` interface.

## Crate structure

```
crates/warp/
  src/
    lib.rs              -- module declarations
    config.rs           -- WARPConfig (l, l1, s, t, etc.)
    errors.rs           -- WARPError, WARPProverError, WARPVerifierError, WARPDeciderError
    types.rs            -- all intermediate instance/witness types
    protocol/
      mod.rs            -- sub-module declarations
      warp.rs           -- WARP struct, prove_with_channel, verify_with_channel, decide
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

All channel operations go through `ia_core::ProverChannel` / `ia_core::VerifierChannel`:

```rust
impl WARP<F, P, C, MT> {
    pub fn prove_with_channel<Ch: ProverChannel>(
        &self, ch: &mut Ch, pk, instances, witnesses, acc_instances, acc_witnesses,
    ) -> Result<(AccumulatorInstances, AccumulatorWitnesses, WARPProofData), WARPProverError>;

    pub fn verify_with_channel<Ch: VerifierChannel>(
        &self, ch: &mut Ch, vk, acc_instance, proof,
    ) -> Result<(), WARPVerifierError>;

    pub fn decide(
        &self, acc_witness, acc_instance,
    ) -> Result<(), WARPDeciderError>;
}
```

The prover absorbs instances and sends proof elements via `ch.send_prover_message()`. The verifier reads them via `ch.read_prover_message()`. Challenges are squeezed via `ch.read_verifier_message()` (prover) and `ch.send_verifier_message()` (verifier). The WARP code never touches a sponge directly.

This means the same protocol code runs against both backends:

- **DSFS** (non-interactive): `dsfs::SpongeProver` / `dsfs::SpongeVerifier` backed by SHA-3 duplex sponge
- **live-channel** (interactive): `LiveProverChannel` / `LiveVerifierChannel` backed by mpsc

## Running the test through DSFS

The integration test creates the sponge channel manually (since WARP takes `&self` parameters that don't fit the type-level `InteractiveReduction` trait directly):

```rust
let protocol_id = spongefish::protocol_id(format_args!("argus::warp::test"));
let session = spongefish::session!("warp test session");
let domsep = DomainSeparator::new(protocol_id).session(session).instance(b"warp-test-inst00");

let mut prover_ch = SpongeProver::new(domsep.std_prover());
let (acc_x, acc_w, proof) = warp.prove_with_channel(&mut prover_ch, &pk, ...)?;
let narg_string = prover_ch.narg_string().to_vec();

let mut verifier_ch = SpongeVerifier::new(domsep.std_verifier(&narg_string));
warp.verify_with_channel(&mut verifier_ch, vk, &acc_x, &proof)?;

warp.decide(&acc_w, &acc_x)?;
```

Prover and verifier share the same domain separator (protocol_id + session + instance tag). The prover produces a NARG string; the verifier replays it, deriving identical challenges from the sponge.

## Why WARP is a single struct, not composed ChainedReductions

The initial design considered decomposing WARP into five `InteractiveReduction`s composed via `ChainedReduction`. This was abandoned because the intermediate types between phases (e.g., `MerkleTree`, `R1CSConstraints`, folded evaluation tables) are not serializable via `spongefish::Encoding`. The `ChainedReduction` machinery requires `TargetInstance`/`TargetWitness` to flow through the DSFS compiler, which assumes they can be encoded.

Instead, WARP is a single struct whose `prove_with_channel` and `verify_with_channel` methods internally organize the logic into the five phases, calling `twin_sumcheck::prove` / `batching_sumcheck::prove` as helper functions. This preserves the core architectural principle -- all sponge operations route through the channel traits -- while keeping implementation practical.

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

## Differences from the original `~/Developer/warp`

The original warp codebase uses spongefish directly (`ProverState` / `VerifierState`) and defines its own `WARPDomainSeparator` that builds a precise absorb/squeeze pattern upfront. The Argus port replaces all spongefish calls with channel trait calls, deferring the sponge management to whichever channel backend is plugged in.

The `efficient-sumcheck` dependency from the original code was removed entirely. Its small set of needed utilities (`Hypercube` iterator, `eq_poly`, `pairwise_reduce`, `tablewise_reduce`) were reimplemented in `utils/poly.rs` to avoid pulling in a newer spongefish revision that would have broken the rest of the Argus workspace.

## Tests

Two integration tests in `tests/warp_test.rs`:

- `warp_bootstrap_prove_verify_decide` -- single proof with empty accumulator (l1=4 fresh instances, l2=0 accumulated). Proves, verifies via NARG string replay, runs decider.
- `warp_full_accumulation_cycle` -- runs 4 bootstrap proofs to build up accumulated state, then a full proof with l1=4 fresh + l2=4 accumulated instances (l=8). Proves, verifies, decides.

Both tests use the BLS12-381 scalar field with a Poseidon hash-chain R1CS relation, Reed-Solomon encoding, and Blake3 Merkle trees.

## Files changed outside `crates/warp/`

- [Cargo.toml](../Cargo.toml) -- added `crates/warp` to workspace members, added `ark-relations`, `ark-r1cs-std`, `ark-crypto-primitives`, `ark-codes`, `thiserror`, `rayon`, `blake3` to workspace deps, added `[patch.crates-io]` for Blake3-enabled `ark-crypto-primitives`
- [dsfs/src/lib.rs](../crates/dsfs/src/lib.rs) -- added `SpongeProver::new()`, `SpongeProver::narg_string()`, `SpongeVerifier::new()` constructors so test code can create sponge channels directly
