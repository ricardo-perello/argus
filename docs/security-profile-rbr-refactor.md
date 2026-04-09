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

## After

```rust
pub struct SecurityProfile {
    /// Classical soundness (no rewinding). Relevant for live-channel.
    pub plain_soundness_error: SecurityErrorBound,
    /// Per-round RBR errors [ε_1^rbr, ..., ε_μ^rbr]. Length = num_rounds.
    pub rbr_soundness_errors: Vec<SecurityErrorBound>,
    /// SR knowledge soundness κ^sr(t). Input to DSFS Theorem 6.2.
    pub sr_knowledge_soundness_error: SecurityErrorBound,
    /// HVZK error z(t). Input to DSFS Theorem 7.1.
    pub hvzk_error: SecurityErrorBound,
    /// Verifier challenge lengths l_V(i) in sponge alphabet units.
    pub verifier_challenge_lengths: Vec<usize>,
}
```

`num_rounds` is now a derived method:

```rust
pub fn num_rounds(&self) -> usize { self.rbr_soundness_errors.len() }
```

SR soundness is now a derived method — not stored:

```rust
pub fn sr_soundness_error(&self) -> SecurityErrorBound {
    self.rbr_soundness_errors
        .iter()
        .fold(SecurityErrorBound::zero(), |acc, e| acc.compose(e))
}
```

`compose()` now concatenates RBR vectors:

```rust
rbr_soundness_errors: [self.rbr_soundness_errors, other.rbr_soundness_errors].concat()
// SR soundness of composed = Σ_i ε_i^rbr (derived on demand, always correct)
```

`NargSecurity::soundness_error(t)` in `crates/dsfs/src/narg_security.rs` now calls `self.ia.sr_soundness_error().evaluate(t)`, which routes through the RBR derivation before applying Theorem 6.1.

---

## Theorem chain (for reference)

```
Protocol author specifies:   ε_i^rbr  per round  (round-by-round soundness)
                                      ↓
ia-core derives:             ε^sr = Σ_i ε_i^rbr  (state-restoration soundness)
                                      ↓
DSFS Theorem 6.1 applies:    ε_NARG(t) ≤ ε^sr(t) + 25t²/|Σ|^c
```

Chiesa–Orrù 2025 (eprint 2025/536) Theorems 6.1/6.2/7.1 take `ε^sr` as input.  
The RBR → SR derivation step is from [CY24] / [BCS16] (not in this paper).

---

## Correctness questions for Alessandro

### Q1 — Exact form of the RBR→SR theorem

We are using:

```
ε^sr(t) = Σ_{i=1}^{μ} ε_i^rbr(t)
```

i.e., the SR soundness of a μ-round protocol is the sum of per-round RBR errors (with the *same* adversary budget `t` plugged into each). Is this the exact statement from [CY24] you have in mind? Alternatives we've seen in the literature:

- `ε^sr(t) ≤ μ · ε^rbr(t)` (uniform per-round error, factor of μ)
- `ε^sr(t) ≤ μ · t · ε^rbr` (factor of both μ and t for statistical/information-theoretic arguments)

The formula we chose is the most natural for heterogeneous per-round errors, but we want to confirm it matches the theorem in CY24.

### Q2 — Should knowledge soundness also have an RBR analog?

Currently `sr_knowledge_soundness_error` is a flat stored field — protocol authors specify it directly. There is no `rbr_knowledge_soundness_errors: Vec<...>`.

- If CY24 also has a round-by-round knowledge soundness notion with an analogous derivation, we should add `rbr_knowledge_soundness_errors` and make `sr_knowledge_soundness_error()` derived.
- If knowledge soundness is only defined at the SR level (as in the DSFS paper's Theorem 6.2), the current flat field is correct.

### Q3 — Is plain soundness composition via union bound correct?

For the live-channel case (no Fiat–Shamir), we compose `plain_soundness_error` via a simple union bound:

```
ε_composed(t) = ε_1(t) + ε_2(t)
```

Is this the right composition rule for classical (plain) soundness in sequential protocol composition, or does it need a different treatment?
