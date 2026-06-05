# Bulletproofs (IPA + Range Proof)

The Bulletproofs example is the workspace's showcase for a **public-coin,
message-passing protocol that needs no oracle**. Everything is the prover
sending group/field elements and the verifier replying with challenges — there
are no commitment openings, no Merkle paths, nothing the byte channel cannot
express. This is the structural opposite of WARP (a commit-and-query / IOP-style
protocol), which is why it maps onto the Argus channel with zero impedance.

The shared IPA toolkit (statement types, vector math, the folding loop) lives in
`crates/argus-examples/src/bulletproofs.rs`; three example binaries each build
one form on top of it.

```bash
cargo run -p argus-examples --bin bulletproof_ipa            # IPA, DSFS
cargo run -p argus-examples --bin bulletproof_ipa -- --live  # IPA, interactive
cargo run -p argus-examples --bin bulletproof_ipa_reduction  # composed IPA (reduction)
cargo run -p argus-examples --bin bulletproof_range          # range proof
```

## 1. Inner-Product Argument (monolithic)

`BulletproofIpa` (Bünz–Bootle–Boneh–Poelstra–Wuille–Maxwell, S&P 2018,
Protocol 1) proves knowledge of vectors `a, b in F^n` with:

```text
P = <a, g> + <b, h> + <a, b> * u
```

for public generator vectors `g, h in G^n`, a point `u`, and a commitment `P`.

```text
Instance = IpaInstance { g, h, u, P }
Witness  = IpaWitness  { a, b }
```

Each round the prover sends two group elements `L, R`; the verifier replies with
one challenge `x`; both sides fold their length-`n` vectors to length `n/2`:

```text
a' = x·a_lo + x⁻¹·a_hi      g' = x⁻¹·g_lo + x·g_hi
b' = x⁻¹·b_lo + x·b_hi      h' = x·h_lo + x⁻¹·h_hi
P' = x²·L + P + x⁻²·R
```

After `log2(n)` rounds the witness is two scalars, sent in the clear. The proof
is **`O(log n)`**: for `n = 8` it is 256 bytes (3 rounds × 2 points + 2 final
scalars). The same `prove`/`verify` body runs non-interactively through DSFS and
interactively through `live-channel`.

Protocol 1 is **not** zero-knowledge (the folded `a, b` are revealed); the
`SecurityProfile` tracks soundness only.

## 2. The IPA as a self-composed reduction

The monolithic loop is exactly `log2(n)` copies of a single reduction. The
example also expresses it that way:

- `IpaFold` — an `InteractiveReduction` with `Source = Target = IpaInstance<G>`
  that performs one round (`n -> n/2`).
- `IpaBase` — an `InteractiveArgument` that decides the size-1 statement
  (`P == a·g₀ + b·h₀ + a·b·u`).

For `n = 8` these compose statically, mirroring the `composition` example:

```rust
type IpaFold2<G>   = ChainedReduction<IpaFold<G>, IpaFold<G>>;
type IpaFold3<G>   = ChainedReduction<IpaFold2<G>, IpaFold<G>>;
type ComposedIpa<G> = ReducedArgument<IpaFold3<G>, IpaBase<G>>;
```

`composed_ipa_matches_monolithic` checks that both forms verify the *same*
statement and produce the same 256-byte transcript. This is the concrete
demonstration that the IR abstraction recovers the hand-written loop.

## 3. Range Proof

`RangeProof` (S&P 2018, §4.2) proves a Pedersen commitment opens to an in-range
value:

```text
V = v·g_base + γ·h_base ,   prove v ∈ [0, 2^N)
```

It reduces the range statement to an inner product and discharges it with the
IPA core (`ipa_prove_core` / `ipa_verify_core`). Transcript shape:

```text
send A, S            squeeze y, z
send T₁, T₂          squeeze x
send τ_x, μ, t̂       squeeze w
run IPA on (g, h' = y⁻ⁱ·h, u·w, P')
```

The verifier checks the `t̂` commitment ties `t̂` to `V`:

```text
t̂·g_base + τ_x·h_base == z²·V + δ(y,z)·g_base + x·T₁ + x²·T₂
δ(y,z) = (z − z²)·<1, yᴺ> − z³·<1, 2ᴺ>
```

then rebuilds the inner-product commitment `P'` from the prover's messages and
runs the IPA verifier.

### Why the `w` challenge

A subtle but load-bearing point. Unlike the standalone IPA — where `P` is given
— the range proof's `P` is *reconstructed by the verifier* from prover-sent
`A, S, T₁, T₂`. With a fixed, known `u`, a malicious prover could fold a `β·u`
term into `A` or `S`, and the verifier's `P' = P + t̂·u` would then carry a
`u`-coordinate of `t̂ + β`, so the IPA would extract vectors whose inner product
need not equal the `t̂` the commitment check validated. Squeezing a fresh `w`
after `τ_x, μ, t̂` and running the IPA with base `u·w` closes this: the prover
must commit before learning `w`. (This is the same "the security profile must
not claim what the protocol does not enforce" discipline applied to WARP.)

Unlike the bare IPA, the range proof **is** zero-knowledge: the blinding
(`α, ρ, s_L, s_R, τ₁, τ₂`) makes it perfect SHVZK, so `hvzk_error = 0`.

## What It Demonstrates

- A mature, deployed protocol fitting the Argus channel with no oracle layer.
- The same body running through DSFS and `live-channel`.
- `InteractiveReduction` self-composition via `ChainedReduction` /
  `ReducedArgument`, recovering a hand-written recursive loop.
- A reduction-to-inner-product (`RangeProof`) reusing the IPA as a subroutine.

## Caveats (example-grade)

- Generators are sampled at random rather than via nothing-up-my-sleeve
  hash-to-curve; fine for completeness demos, not for production binding.
- The `SecurityProfile` per-round errors are coarse `O(1/|F|)` placeholders. The
  precise IPA knowledge-soundness bound (BCCGP16 / Bulletproofs §3, forking
  lemma over `2 log n + 1` transcripts) and the range proof's per-round
  decomposition are left as TODOs in the source.
