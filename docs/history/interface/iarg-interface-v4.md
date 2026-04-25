# IA v4: Security Metadata and DSFS Bounds

## Motivation

v3 established a clean channel-based IA/IOR interface, but it did not expose protocol-level security metadata in a structured way.

For DSFS, we need IA metadata that can be combined with sponge parameters to derive final NARG bounds as functions of adversarial query budget `t`, following:

- Theorem 1 (informal): soundness and knowledge soundness
- Theorem 2 (informal): adaptive zero-knowledge from HVZK

This version adds explicit security metadata to IA/IOR traits and a DSFS-side bound evaluator.

## The formulas used

Given an interactive protocol `IP`, and `NARG = DSFS[IP, cdc, delta]`:

```text
eps_NARG(t)   <= eps_sr_IP(t)   + 25 t^2 / |Sigma|^c
kappa_NARG(t) <= kappa_sr_IP(t) + 25 t^2 / |Sigma|^c
```

```text
z_NARG(t) <= z_IP
          + t / |Sigma|^min(delta, c)
          + t * sum_i ceil(l_V(i) / r) / |Sigma|^(r + c)
```

Where:

- `|Sigma|` is sponge alphabet size
- `c` is sponge capacity
- `r` is sponge rate
- `delta` is codec/domain parameter
- `l_V(i)` is verifier challenge length for round `i`

## Core interface change

### `SecurityErrorBound`: composable error bound

Error bounds in the paper are functions of the adversary's query budget `t` -- for example `eps_sr_IP(t)`. We represent this with `SecurityErrorBound`, a sum-of-function-pointers type that supports additive composition without closures or heap-allocated trait objects:

```rust
pub struct SecurityErrorBound(Vec<fn(u64) -> f64>);
```

- `SecurityErrorBound::new(f)` -- single-term error function
- `SecurityErrorBound::zero()` -- identically zero for all `t`
- `evaluate(t)` -- sum all terms at query budget `t`
- `compose(&other)` -- additive: `(self + other)(t) = self(t) + other(t)`, implemented as vector concatenation

For information-theoretic protocols where the error is constant in `t`, use `SecurityErrorBound::new(|_t| constant)`. For computational settings where the bound genuinely depends on `t`, the function pointer can encode that dependency. Generic protocols that need type-level info (e.g. field size) work naturally because Rust monomorphizes each impl -- the function pointer is specialized per concrete type.

### `SecurityProfile`

```rust
pub struct SecurityProfile {
    pub soundness_error: SecurityErrorBound,
    pub knowledge_soundness_error: SecurityErrorBound,
    pub hvzk_error: SecurityErrorBound,
    pub num_rounds: usize,
    pub verifier_challenge_lengths: Vec<usize>,
}
```

Both metadata traits expose:

```rust
fn security() -> SecurityProfile
```

Specifically:

- `InteractiveArgument::security() -> SecurityProfile`
- `InteractiveReduction::security() -> SecurityProfile`

This keeps transcript logic in DSFS while letting protocols report their own IA-level assumptions and bounds as functions of `t`.

## Composition behavior

Security metadata composes automatically:

- `ChainedReduction<First, Second>` uses `First::security().compose(&Second::security())`
- `ReducedArgument<R, A>` uses `R::security().compose(&A::security())`

`SecurityProfile::compose` calls `SecurityErrorBound::compose` (vector concatenation) on each error field and concatenates challenge-length vectors.

This matches a conservative union-bound style composition and gives `FullWARP = ReducedArgument<WARPReduction, WARPDeciderIA>` a derived profile automatically.

## DSFS security API

The DSFS layer owns the sponge configuration. Callers never need to specify sponge parameters for the standard hash (Shake128 / Keccak-f[1600]).

### Standard usage

```rust
let sec = dsfs::security::<Schnorr<G>>();
println!("{:.1} bits", sec.soundness_bits(1 << 40));
```

### Types

```rust
pub struct SpongeParams {
    pub alphabet_size: f64,
    pub capacity: u64,
    pub rate: u64,
    pub delta: u64,
}

pub const STD_SPONGE_PARAMS: SpongeParams = SpongeParams {
    alphabet_size: 256.0, capacity: 32, rate: 168, delta: 1,
};

pub struct NargSecurity {
    pub ia: SecurityProfile,
    pub sponge: SpongeParams,
}
```

### Free functions (standard sponge)

- `dsfs::security::<IA>()` -- NARG security for an `InteractiveArgument`
- `dsfs::reduction_security::<IR>()` -- NARG security for an `InteractiveReduction`

### Constructors on `NargSecurity`

- `NargSecurity::for_ia::<IA>()` / `NargSecurity::for_reduction::<IR>()` -- standard sponge
- `NargSecurity::for_ia_with::<IA>(sponge)` / `NargSecurity::for_reduction_with::<IR>(sponge)` -- custom sponge (Poseidon, etc.)

### Bound methods on `NargSecurity`

- `soundness_error(t)` implementing Theorem 1 bound
- `knowledge_soundness_error(t)` implementing Theorem 1 bound
- `zk_error(t)` implementing Theorem 2 bound
- `soundness_bits(t)`, `knowledge_soundness_bits(t)`, `zk_bits(t)` as `-log2(error)`

## Architectural invariants preserved

- IA/IOR traits describe protocol structure and metadata only.
- DSFS remains the only layer performing sponge operations.
- Transcript ordering invariants remain unchanged.
- Security-bound computation remains centralized in DSFS.

## Practical guidance for protocol implementers

When implementing `security()`:

- `soundness_error`: provide `SecurityErrorBound` for state-restoration soundness as a function of `t`
- `knowledge_soundness_error`: provide `SecurityErrorBound` for state-restoration knowledge soundness
- `hvzk_error`: provide `SecurityErrorBound` for honest-verifier ZK error
- `num_rounds`: set protocol round count
- `verifier_challenge_lengths`: provide per-round challenge lengths in sponge alphabet units

For IT protocols where the error is constant (e.g. `dk/|F|` for sumcheck), use `SecurityErrorBound::new(|_t| constant)`. For computational settings, encode the `t`-dependence in the function pointer. For protocols with runtime-dependent parameters, return a conservative static profile in `security()`, and provide an additional protocol-specific helper for tighter instance/config-specific estimates.

## File references

- IA interface: [../crates/ia-core/src/lib.rs](../crates/ia-core/src/lib.rs)
- DSFS bounds: [../crates/dsfs/src/lib.rs](../crates/dsfs/src/lib.rs)
- WARP IA/IR impls: [../crates/warp/src/protocol/ir.rs](../crates/warp/src/protocol/ir.rs)
- Prior interface version: [iarg-interface-v3.md](iarg-interface-v3.md)
