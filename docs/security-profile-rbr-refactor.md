# Security Profile Refactor: RBR Soundness & Correct Composition

Branch: `security-profile-rbr-refactor`  
Commit: `168d1ea`

---

## Before

`SecurityProfile` had three flat error bounds:

```rust
pub struct SecurityProfile {
    pub soundness_error: SecurityErrorBound,          // ε^sr(t) — but labelled ambiguously
    pub knowledge_soundness_error: SecurityErrorBound, // κ^sr(t)
    pub hvzk_error: SecurityErrorBound,               // z(t)
    pub num_rounds: usize,
    pub verifier_challenge_lengths: Vec<usize>,
}
```

`compose()` did a union bound on `soundness_error` directly:

```rust
soundness_error: self.soundness_error.compose(&other.soundness_error),
// → ε^sr_composed(t) = ε^sr_1(t) + ε^sr_2(t)
```

**Problem:** SR soundness is *not* trivially composable via union bound. An SR adversary with budget `t` can split its state-restoration queries between sub-protocols in ways that a simple union bound does not correctly account for. The correct composition level is round-by-round (RBR): RBR errors concatenate, and SR is then *derived* from the combined RBR profile.

---

## After (current state)

```rust
pub struct SecurityProfile {
    /// Classical soundness (no rewinding). Relevant for live-channel.
    pub plain_soundness_error: SecurityErrorBound,
    /// Per-round RBR errors [ε_1^rbr, ..., ε_μ^rbr]. Length = num_rounds.
    pub rbr_soundness_errors: Vec<SecurityErrorBound>,
    /// Per-round RBR knowledge errors [κ_1^rbr, ..., κ_μ^rbr]. Length = num_rounds.
    pub rbr_knowledge_soundness_errors: Vec<SecurityErrorBound>,
    /// HVZK error z(t). Input to DSFS Theorem 7.1.
    pub hvzk_error: SecurityErrorBound,
    /// Verifier challenge lengths l_V(i) in sponge alphabet units.
    pub verifier_challenge_lengths: Vec<usize>,
}
```

`num_rounds` and SR-level errors are now derived:

```rust
pub fn num_rounds(&self) -> usize { self.rbr_soundness_errors.len() }

// CY24 Theorem 31.2.1 (tighter heterogeneous form):
//   ε^sr(t) ≤ t * max_i ε_i^rbr(t) + Σ_i ε_i^rbr(t)
pub fn sr_soundness_error(&self, t: u64) -> f64 { ... }

// CY24 Theorem 31.3.1 (tighter heterogeneous form):
//   κ^sr(t) ≤ t * max_i κ_i^rbr(t) + Σ_i κ_i^rbr(t)
pub fn sr_knowledge_soundness_error(&self, t: u64) -> f64 { ... }
```

`compose()` now concatenates both RBR vectors:

```rust
rbr_soundness_errors: [self.rbr_soundness_errors, other.rbr_soundness_errors].concat()
rbr_knowledge_soundness_errors: [self.rbr_knowledge_soundness_errors, other.rbr_knowledge_soundness_errors].concat()
// SR soundness/knowledge derived on demand from the combined vector
```

`NargSecurity::soundness_error(t)` in `spongefish::dsfs` calls
`self.ia.sr_soundness_error(t)` and `self.ia.sr_knowledge_soundness_error(t)`.

---

## Theorem chain (for reference)

```
Protocol author specifies:   ε_i^rbr  and  κ_i^rbr  per round
                                       ↓
ia-core derives (CY24 Thm 31.2.1):  ε^sr(t) ≤ t·max_i ε_i^rbr(t) + Σ_i ε_i^rbr(t)
ia-core derives (CY24 Thm 31.3.1):  κ^sr(t) ≤ t·max_i κ_i^rbr(t) + Σ_i κ_i^rbr(t)
                                       ↓
DSFS Theorem 6.1:    ε_NARG(t) ≤ ε^sr(t) + 25t²/|Σ|^c
DSFS Theorem 6.2:    κ_NARG(t) ≤ κ^sr(t) + 25t²/|Σ|^c
```

Why tighter heterogeneous form (not CY24's uniform `(t+k)·ε^rbr`):
- The `t` adversarial SR moves each attack the worst-case round (max term).
- The `k` protocol completion moves each use their own round's error (sum term).
- The uniform form `(t+k)·max` upper-bounds the sum term by `k·max`.
- For protocols with heterogeneous per-round errors the tighter form is strictly better.

---

## Q1 — Exact form of the RBR→SR theorem (resolved)

We confirmed via CY24 Chapter 31:

```
ε^sr(t) ≤ t · max_i ε_i^rbr(t) + Σ_i ε_i^rbr(t)
```

This is the tighter heterogeneous form derived from the proof of Theorem 31.2.1.
The simpler `(t+k)·ε^rbr` (uniform per-round) is a valid but looser upper bound.

## Q2 — Should knowledge soundness also have an RBR analog? (resolved)

Yes. CY24 Theorem 31.3.1 gives an exact parallel:

```
κ^sr(t) ≤ t · max_i κ_i^rbr(t) + Σ_i κ_i^rbr(t)
```

`rbr_knowledge_soundness_errors` was added alongside `rbr_soundness_errors`.
Both compose by concatenation; both are derived at the SR level on demand.

## Q3 — Is plain soundness composition via union bound correct? (still open)

For the live-channel case (no Fiat–Shamir), `plain_soundness_error` is composed
additively (union bound):

```
ε_composed(t) = ε_1(t) + ε_2(t)
```

This is correct for sequential public-coin composition under standard (non-SR)
soundness: an adversary that breaks the composed protocol must break either the
first or the second sub-protocol, and a union bound applies. No SR rewind budget
is involved.

---

## Phase 2 — `SecurityErrorBound` closure refactor

Previously `SecurityErrorBound` stored `Vec<fn(u64) -> f64>` — bare function
pointers with no captured state. This made it impossible to close over code
parameters (field size, code distance, list sizes) without a workaround like
generating `d` copies of `1/|F|` to represent `d/|F|`.

### Change

```rust
// BEFORE
pub struct SecurityErrorBound(Vec<fn(u64) -> f64>);
pub fn new(f: fn(u64) -> f64) -> Self { ... }

// AFTER
use alloc::sync::Arc;
pub struct SecurityErrorBound(Vec<Arc<dyn Fn(u64) -> f64 + Send + Sync>>);
pub fn new(f: impl Fn(u64) -> f64 + Send + Sync + 'static) -> Self { ... }
```

`compose()` changed from `extend_from_slice` (requires `Copy`) to
`terms.extend(self.0.iter().cloned())` (`Arc::clone` is cheap).

All existing call sites that pass bare `fn` items compile unchanged — every
`fn item` implements `Fn + Send + Sync + 'static`.

### Impact on WARP

The `make_deg_bound` hack in `ir.rs` (which generated `d` copies of `1/|F|`
and composed them) was replaced with a clean closure:

```rust
let field_bits = F::MODULUS_BIT_SIZE as i32;
let make_deg_bound = |deg: usize| -> SecurityErrorBound {
    SecurityErrorBound::new(move |_t| (deg as f64) * 2_f64.powi(-field_bits))
};
```

This also unblocks per-round errPG closures that capture round index and code
parameters — both of which vary per round and cannot be encoded as bare fn
pointers.

---

## Phase 3 — `CodeSecurityParams` trait and full WARP paper bounds

### `CodeSecurityParams` (ia-core)

A new trait in `ia-core::security` exposes the three code-level parameters
needed to compute the full soundness bounds from eprint 2025/753:

```rust
pub trait CodeSecurityParams {
    fn distance(&self) -> f64;                           // δ = 1 − rate
    fn list_size_bound(&self) -> f64;                    // |Λ(C, δ)|
    fn proximity_generator_error(&self, degree: usize) -> f64; // err_PG(C, d, δ)
}
```

Exported from `ia_core::` alongside `ProtocolSecurity`.

### `ReedSolomonParams` (warp crate)

The orphan rule prevents `impl CodeSecurityParams for ReedSolomon<F>` in the
`warp` crate (both the trait and `ReedSolomon<F>` are foreign). Solution: a
local newtype `ReedSolomonParams { n, k, field_size_bits }` in
`crates/warp/src/rs_params.rs`:

```rust
impl CodeSecurityParams for ReedSolomonParams {
    fn distance(&self) -> f64 { 1.0 - self.k as f64 / self.n as f64 }
    fn list_size_bound(&self) -> f64 { self.n as f64 }  // conservative; TODO tighten
    fn proximity_generator_error(&self, degree: usize) -> f64 {
        (degree + 1) as f64 * (self.n as f64).powi(2) * 2_f64.powi(-(self.field_size_bits as i32))
        // BCIKS20 bound: err_PG(C, d, δ) ≤ (d+1) · n² / |F|
    }
}
```

### `WARPReduction` changes

Three new fields added; `Default` impl removed:

```rust
pub struct WARPReduction<F, P, C, MT> {
    pub log_l: usize,
    pub log_n: usize,
    pub log_m: usize,
    pub code_params: ReedSolomonParams,   // n, k, |F|-bits
    pub ood_samples: usize,               // WARPConfig.s
    pub shift_queries: usize,             // WARPConfig.t
    _phantom: PhantomData<(F, P, C, MT)>,
}
```

### Full paper bounds in `security()`

Per eprint 2025/753:

```
Twin sumcheck round j (0-indexed):
  ε_j^rbr = (twin_deg / |F|) + (ℓ / 2^j) · err_PG(C, 2, δ)
  where twin_deg = 1 + max(log_n + 1, log_m + 2)

Batching sumcheck round (all log_n rounds):
  ε_i^rbr = 2 / |F|

Commitment-phase (one-time, non-SR, in plain_soundness_error):
  |Λ|² · log_n / |F|  +  (1 − δ)^shift_queries  +  |Λ| · log_m / |F|
```

The commitment-phase terms are placed in `plain_soundness_error` rather than
`rbr_soundness_errors` because they do not correspond to interactive rounds and
therefore do not participate in the SR adversary budget. This placement is pending
confirmation with Chiesa (Q2 from the meeting sheet).

### Test migration

Both `warp_test.rs` tests that previously used `WARPReduction::default()` or
`FullWARP::default()` now construct with explicit parameters:

```rust
let code_params = ReedSolomonParams::new(
    code.code_len(), code.message_len(), Fp::MODULUS_BIT_SIZE,
);
let ir = WARPReduction::<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>::new(
    log2(l1) as usize, log2(code.code_len()) as usize, log2(r1cs.m) as usize,
    code_params, 8, 7,
);
```
