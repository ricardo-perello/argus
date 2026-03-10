# Interactive Reduction Interface

## Background

An Interactive Argument (IA) verifier outputs **accept/reject**.
An Interactive Oracle Reduction (IOR) verifier outputs a **new instance** of a target relation.

WARP ([ePrint 2025/753](https://eprint.iacr.org/2025/753), Bunz-Chiesa-Fenzi-Wang) is an accumulation scheme built from an IOR of proximity. To express WARP-style protocols through Argus, we added a first-class IOR interface alongside the existing IA interface.

## What we added

### ia-core: three new traits

The channel traits (`SendProverMessage`, `ReadProverMessage`, `SendVerifierMessage`, `ReadVerifierMessage`) are shared between IA and IOR -- the interaction pattern is identical. Only the protocol-level traits differ:

- **`InteractiveReduction`** -- metadata: `SourceInstance`, `TargetInstance`, `Witness`, `protocol_id()`
- **`ReduceProve<P>`** -- prover sends oracle messages through the channel
- **`ReduceVerify<V>`** -- verifier reads messages, derives challenges, computes and returns the `TargetInstance`

The key difference from the IA traits: `ReduceVerify::verify()` returns `VerificationResult<Self::TargetInstance>` instead of `VerificationResult<()>`.

### dsfs: two new compiler functions

- **`prove_reduction<IR>()`** -- same sponge mechanics as `prove()`, bounded on `IR: ReduceProve<SpongeProver>`
- **`verify_reduction<IR>()`** -- same sponge setup as `verify()`, but returns `VerificationResult<IR::TargetInstance>`

The `SpongeProver` and `SpongeVerifier` structs are reused as-is. The underlying Fiat-Shamir transformation is identical -- same sponge, same absorb/squeeze ordering, same NARG output format.

### warp_accumulate example

A runnable end-to-end example in `crates/argus-examples/src/bin/warp_accumulate.rs` demonstrating the full pipeline:

1. Define an IOR that accumulates n claims into one via random linear combination
2. Prover sends each witness value through the channel
3. Verifier reads them, squeezes random alpha, computes `acc = sum(alpha^i * x_i)` for both claims and values
4. Verifier returns the accumulated pair as the target instance
5. A separate **decider** checks `acc_claim == acc_value`

Soundness: if any `c_i != w_i`, then `acc_claim != acc_value` with probability >= `1 - n/|F|` by Schwartz-Zippel.

## Limitations of warp_accumulate.rs

The example is a **toy accumulation IOR**, not the real WARP protocol. Specifically:

- **No proximity testing.** WARP reduces a proximity claim (closeness to a Reed-Solomon codeword). Our example reduces an equality claim via random linear combination. The structure is the same (IOR + Fiat-Shamir), but the actual reduction is trivial.
- **No oracle commitments.** In WARP, the prover sends oracle messages as Merkle-committed codewords. Our example sends raw field elements.
- **No multi-round folding.** WARP's IOR iteratively halves the code length across multiple rounds. Our example is a single-round reduction.
- **No Reed-Solomon encoding.** The prover doesn't encode the witness as a codeword.
- **No decider complexity.** The decider is a single equality check, not a proximity check against a code.

The example demonstrates that the `InteractiveReduction` -> DSFS pipeline works end-to-end, but implementing the actual WARP IOR from the paper would require building the full proximity reduction (Reed-Solomon folding, Merkle commitments, multi-round interaction, proximity decider).

## Status of the warp repo (`~/Developer/warp`)

The copy of the warp codebase we reviewed was obtained from Alex Havlin. The original author is Andrew Zitek (`z-tech` in the TODO comments). The version we have may be outdated -- a more current version may exist elsewhere.

### What works

The supporting infrastructure is real and substantial:

- **Reed-Solomon** encode/decode over FFT domains
- **R1CS relations**: identity, hash preimage (Poseidon), is-prime (Pratt certificate), Merkle inclusion
- **Poseidon Merkle trees** with coset proofs, prefix adapters, and batch operations
- **Baseline accumulator** (`src/accumulator/baseline/`): fully working commit/open/verify using Groth16 proofs + Merkle trees over the is-prime relation. This is a naive approach (prove each relation independently with Groth16, commit via Merkle root), not WARP-style accumulation.

### What does not work

The WARP-specific accumulator (`src/accumulator/warp/`) is scaffolding:

- `commitment()` returns `F::zero()`
- `open()` returns `Ok(vec![F::from(index as u64)])`
- `verify()` returns `false`
- `Proof` type is `Vec<F>` with a `// TODO(z-tech)` comment

The only implemented part of `commit()` is sponge initialization: absorbing the circuit description and public config. The actual protocol logic (parse, reduce, accumulate -- noted as TODOs in comments) was never filled in.

Additionally, the repo's dev-dependencies include `procfs` (Linux-only), pulled in by `merkle/benches/merkle_bench.rs`, which prevents `cargo test` from running on macOS.

### Implication

Our `warp_accumulate.rs` already does more than the WARP accumulator in that repo -- it completes a full prove/verify cycle end-to-end via DSFS. Building the real WARP IOR would mean implementing it from the paper ([ePrint 2025/753](https://eprint.iacr.org/2025/753)), not porting existing code.
