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

`NargSecurity::soundness_error(t)` in `crates/dsfs/src/narg_security.rs` calls
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
