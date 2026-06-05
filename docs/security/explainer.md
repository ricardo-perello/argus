# Argus Security, From Scratch

A guided tour of what Argus's security layer does, written for someone who has
**not** seen it before and does **not** already know the soundness games or the
theorems involved. By the end you should understand what the number
"128 bits of soundness" means here, and where every bit of it comes from.

The terse reference docs in this folder (`overview.md`, `rbr-and-sr.md`,
`dsfs-bounds.md`, …) assume the background this document builds.

---

## 0. The one-sentence pitch

> When you turn an interactive protocol into a single non-interactive proof,
> Argus computes **exactly how much security that proof has** — as an explicit
> function of how hard the attacker is willing to work — and shows where each
> term comes from.

Most proof libraries give you a proof. Argus also gives you a *budget*: the
protocol author declares the security of each round, and the compiler assembles
those into a concrete bound for the final proof.

---

## 1. The setting

A **prover** wants to convince a **verifier** that some statement is true — and
often that it *knows a secret* (a witness) behind it.

- **Interactive protocol.** Prover and verifier take turns. Crucially the
  verifier's messages are just **random coins** ("public-coin"): the verifier
  sends a random challenge, the prover must answer consistently. A cheating
  prover can't predict the challenge, so it can't prepare a fake answer in
  advance — that's where security comes from.

- **Non-interactive proof (Fiat–Shamir).** Interaction is inconvenient: you'd
  rather post one proof string anybody can check later. The **Fiat–Shamir**
  trick removes the verifier: replace each random challenge with the output of a
  hash function applied to the transcript so far. Argus's `dsfs` backend does
  exactly this, using a **duplex sponge** (Keccak) as the hash — hence *DSFS*,
  Duplex-Sponge Fiat–Shamir.

There is a price. Once the "random" challenges are produced by a hash the prover
can evaluate itself, the prover can **retry**: compute a challenge, dislike it,
tweak its message, and hash again — as many times as it's willing to pay for.
Security can no longer be "the attacker gets one shot"; it must account for an
attacker that grinds. Quantifying that is the whole game.

---

## 2. Security as a game

Every security notion below has the same shape:

> Set up a game between an honest verifier and a malicious prover. The prover
> **wins** under some bad condition. The protocol has **error `ε`** if no prover
> wins with probability more than `ε`.

Smaller `ε` = more secure. We usually report `-log2(ε)` and call it **bits**:
`ε = 2^-128` is "128 bits of security."

We define the games one at a time.

### 2.1 Plain soundness

- **Statement is false.** A cheating prover runs the protocol once against the
  honest verifier.
- **Wins** if the verifier accepts.
- Error: `ε_sound`.

This is the classic notion. It's the right one for the **interactive** setting
(the `live-channel` backend), where the verifier's coins are genuinely random
and out of the prover's control — one shot.

### 2.2 The Fiat–Shamir twist: state-restoration (SR) soundness

One shot is *not* the right model once challenges come from a hash. The prover
can explore a whole **tree** of attempts: try a message, see the resulting
challenge, back up, try a different message, branch again, …

We model this with the **state-restoration (SR) game** (Chiesa–Yogev book,
Ch. 12):

- The verifier is **stateful and resettable**. The prover may, at any point,
  rewind to an earlier transcript prefix and ask for a fresh challenge from
  there.
- Each challenge request costs **one move**. The prover has a **budget `t`** —
  think of `t` as "how many hash evaluations the attacker can afford" (e.g.
  `t = 2^40` for a well-funded attacker, `2^60` for a nation-state).
- **Wins** if, within `t` moves, it assembles a full accepting transcript for a
  false statement.
- Error: `ε^sr(t)` — and note it **grows with `t`**, because more retries means
  more chances.

SR soundness is the property the Fiat–Shamir / DSFS theorems actually consume.
If a protocol is SR-sound, its Fiat–Shamir compilation is sound.

### 2.3 Round-by-round (RBR) soundness — the author-friendly notion

SR soundness is awkward to prove directly (you'd reason about an attacker
exploring an exponential tree). **Round-by-round (RBR) soundness** is the
tractable, local condition that protocol authors actually establish. It comes
from Canetti–Chen–Holmgren et al. (2018) and is the backbone of the Chiesa–Yogev
treatment (Ch. 31).

The picture turns on one word: **doomed**. Call a partial transcript *doomed*
when the cheating prover has already lost on it — whatever messages it sends from
here, the verifier will reject at the end, *unless* some future verifier
challenge happens to bail it out. Read it as "dead unless rescued by luck."

For a **false** statement the prover is doomed before it even starts: there is no
honest way to finish. Round-by-round soundness pins down the *only* way it could
recover, with four rules:

1. A false statement's transcript **starts doomed**.
2. A **prover message can't escape doom** — you can't talk your way out of a
   false claim by picking a clever message.
3. A **verifier challenge can escape doom**, but only by accident — with
   probability at most `εᵢ^rbr` in round `i`.
4. A transcript still doomed at the **end is rejected**.

So the only road to a forged proof is to **get lucky on a challenge** and flip a
doomed prefix into a live one:

> **`εᵢ^rbr`** = the chance that round `i`'s random challenge rescues a doomed
> prover. That single per-round number is what a protocol author proves.

Why per round? Because rounds differ in how rescuable they are. In sum-check,
round `i` sends a degree-`dᵢ` polynomial, and a lying prover is rescued only if
the challenge lands on a root of an error polynomial — probability `dᵢ / |F|`
(Schwartz–Zippel). In Schnorr (a single round), escaping means guessing the
challenge outright — probability `1/q`. Recording one error *per round* keeps
Argus precise and lets protocols **compose** (Section 5).

### 2.4 Knowledge soundness

Often "the statement is true" is too weak; we want "the prover **knows** a
witness." This is formalized by an **extractor**: a machine that, given access to
any prover convincing enough to be accepted, recovers a valid witness. Knowledge
soundness error `κ` bounds how often extraction fails. It has the same per-round
RBR form, `κᵢ^rbr`, and the same SR lift.

### 2.5 Zero-knowledge (HVZK)

A proof should leak nothing beyond the truth of the statement. Formalized by a
**simulator** that produces transcripts indistinguishable from real ones
*without* the witness. The (honest-verifier) zero-knowledge error `z` bounds how
distinguishable they are. Schnorr, for instance, has perfect HVZK (`z = 0`).

---

## 3. The bridge: how the games connect

Argus never asks an author for SR or Fiat–Shamir numbers directly. The author
gives **per-round RBR** numbers, and two theorems lift them.

### Step 1 — RBR ⇒ SR (Chiesa–Yogev Thm 31.2.1)

Over `t` retries plus `k` rounds, each "move" escapes doom with probability at
most its round's error. Summing the chances gives, in the form Argus uses:

```
  eps^sr(t)  <=  t * max_i eps_i^rbr  +  sum_i eps_i^rbr
```

Read it as two parts:

- `t * max_i eps_i^rbr` — the `t` adversarial retries; the attacker aims every
  one at the *weakest* round.
- `sum_i eps_i^rbr` — the `k` rounds of the final transcript, each paying its
  own error.

Two sanity checks fall out: at `t = 0` (no retries) it's just `sum_i eps_i`,
which is exactly ordinary soundness; with one round it's `(t+1) * eps`. (The
textbook *states* a slightly looser `(t+k) * max`; Argus uses the tighter
`t*max + sum`, which the same proof supports. The knowledge version, Thm 31.3.1,
is identical with `kappa` in place of `eps`.)

### Step 2 — SR ⇒ non-interactive proof (DSFS, Chiesa–Orrù 2025)

Fiat–Shamir through a duplex sponge adds **one more way to cheat**: attack the
sponge itself (find a collision in the permutation). So the final
non-interactive (NARG) error is the SR error plus a sponge term:

```
  eps_NARG(t)  <=  eps^sr(t)  +  25 * t^2 / |Sigma|^c
```

where `|Sigma|` is the sponge alphabet size and `c` its capacity (together
`|Sigma|^c` is the sponge's collision resistance, ~`2^256` for the standard
Keccak setting). Knowledge soundness gets the same extra term; zero-knowledge
has its own sponge formula (DSFS Thm 7.1).

### The whole chain at a glance

```
   per-round RBR errors            per-round RBR knowledge errors
   [eps_1, ..., eps_k]             [kappa_1, ..., kappa_k]
          | Thm 31.2.1                    | Thm 31.3.1
          v                               v
   eps^sr(t) = t*max + sum         kappa^sr(t) = t*max + sum
          | DSFS Thm 6.1                  | DSFS Thm 6.2
          v                               v
   eps_NARG(t) = eps^sr + sponge   kappa_NARG(t) = kappa^sr + sponge
```

The point of keeping per-round errors all the way down is that the SR collapse
happens **once, at the very end** — after any composition — which is tighter
than collapsing early.

---

## 4. What a protocol author writes: the `SecurityProfile`

All of the above is packaged in one struct
(`crates/ia-core/src/security/plain.rs`):

```rust
pub struct SecurityProfile {
    pub plain_soundness_error: SecurityErrorBound,          // eps(t): interactive / one-shot
    pub rbr_soundness_errors: Vec<SecurityErrorBound>,      // [eps_1, ..., eps_k], one per round
    pub rbr_knowledge_soundness_errors: Vec<SecurityErrorBound>, // [kappa_1, ..., kappa_k]
    pub hvzk_error: SecurityErrorBound,                     // z(t)
    pub verifier_challenge_lengths: Vec<usize>,             // challenge sizes (for the ZK sponge term)
}
```

A `SecurityErrorBound` is just "a function of the attacker budget `t`" (you can
capture protocol parameters like field size or code distance inside it). The
author fills in the per-round errors; Argus derives `eps^sr`, `kappa^sr`, and the
final NARG bounds.

**The errors depend on the statement.** A bigger circuit is easier to cheat, so
the profile is built *for a concrete instance* (or for a worst-case size bound) —
not as a single global constant. That's what `profile_for_concrete_instance(...)`
and the `InstanceParams` / `InstanceBound` associated types are for
(`instance-aware-security.md`).

### Worked example: Schnorr

Schnorr (knowledge of `x` with `X = x·G`) is one round; a cheating prover must
guess the challenge, so `eps_1^rbr = 1/q` where `q` is the scalar field size. Its
profile (see `crates/argus-examples/src/bin/schnorr.rs`) says:

- `rbr_soundness_errors = [1/q]`, `rbr_knowledge_soundness_errors = [1/q]`
- `hvzk_error = 0` (perfect zero-knowledge)

Over curve25519 (`q ~ 2^252`) compiled with the standard Keccak sponge, at an
attacker budget of `t = 2^40` the derived NARG soundness comes out **above 128
bits** — and the test `schnorr_narg_soundness_bits_above_128` checks exactly
that. You can see all the terms by calling the API in Section 7.

---

## 5. Composition: big protocols from small ones

Argus has two protocol shapes:

- **Interactive Argument (IA)** — verifier outputs accept/reject.
- **Interactive Reduction (IR)** — verifier outputs a *new, smaller* statement
  for someone else to check.

You build pipelines: chain reductions (`IR ∘ IR`), then cap with an argument
(`IR ∘ IA`). The classic example is sum-check: a reduction from "this big sum is
correct" to "this single evaluation is correct," followed by a check of that
evaluation.

Security composes cleanly, and this is where per-round storage pays off:

- **RBR error vectors are concatenated** — the composed protocol's rounds are
  just the first protocol's rounds followed by the second's.
- The downstream protocol is evaluated against a **worst-case bound on the
  statement the reduction hands it** (not the honest one). The reduction's
  `target_bound_for_source_bound(...)` produces that bound.
- The SR collapse (`t*max + sum`) is applied **once** to the full concatenated
  vector — tighter than composing SR numbers.

> **Author beware (a real footgun):** the "worst-case target bound" must cover
> *every statement a cheating prover could steer the verifier to*, not just the
> honest output. The type system can't enforce this; getting it wrong silently
> under-counts the composed soundness. This is the one place to be careful when
> writing a reduction's security.

---

## 6. Preprocessing: when the statement has a big fixed part

Many real systems prove statements of the form "for this fixed circuit `i`, here
is a witness for input `x`." The circuit `i` (the **index**) is huge and reused
across many small inputs. Preprocessing splits the work:

- An **offline phase** runs once on the index, producing a **prover key** and a
  **verifier key**.
- An **online phase** proves/verifies each `(x, w)` cheaply against those keys.

The verifier key **commits to the index**, so a proof is bound to *that* circuit
— a proof made for circuit `i` must not verify against a different circuit `i'`.
That binding is itself a security assumption, and it carries a small extra
soundness cost: the **offline binding error**.

How big is it? It depends on *how succinct the verifier is* (Chiesa–Yogev §32.7,
the "COS" transformation):

- **The verifier holds the full index** (re-checks everything against the real
  circuit). Then there is **no commitment a prover can equivocate** — the offline
  binding error is **zero**. The index is only hashed for domain separation, and
  that's already covered by the sponge term from Section 3.
- **The verifier is succinct** — it holds only a short Merkle commitment to the
  index and the prover *opens* it during the proof. Now a prover could try to
  cheat the commitment, costing
  `(t + 2*l_0)^2 / 2^(lambda+1) + t^2 / 2^(lambda+1)`, where `l_0` is the
  committed index length and `lambda` the commitment's collision resistance.

Argus expresses this with one required method on the preprocessing security
traits (`offline_binding_error`, in
`crates/ia-core/src/security/preprocessing.rs`). It is added to the soundness and
knowledge bounds, **never to zero-knowledge** (the offline phase doesn't touch
ZK). **WARP** today is the first case (full-index verifier), so it returns zero —
with the succinct-verifier term documented and ready for when WARP's verifier
becomes succinct (`crates/warp/src/protocol/ir.rs`).

---

## 7. Reading the output

Compiled-proof security lives in `NargSecurity` (the `dsfs` backend). Build it
for a protocol and instance, then ask:

```rust
let sec = dsfs::security_for_concrete_instance(&schnorr, &instance);

let t = 1u64 << 40;               // attacker budget: 2^40 hash queries
sec.soundness_error(t);           // eps_NARG(t)            (probability)
sec.soundness_bits(t);            // -log2(eps_NARG(t))     (e.g. > 128)
sec.knowledge_soundness_bits(t);  // knowledge version
sec.zk_bits(t);                   // zero-knowledge
```

Interpretation: a result such as `soundness_bits(2^40) = 130` means "an attacker
who can afford `2^40` hash evaluations still has at most `2^-130` chance of
forging a proof for a false statement." If you expect stronger attackers,
evaluate at a larger `t` and watch the number drop — that decline *is* the
Fiat–Shamir cost, made explicit.

---

## 8. Where it lives, and what to read next

In this repo:

- `crates/ia-core/src/security/plain.rs` — `SecurityProfile`, the SR derivation.
- `crates/ia-core/src/security/preprocessing.rs` — index-aware / preprocessing security.
- `crates/ia-core/src/interactive/composition/` — how composition composes profiles.
- the DSFS backend (`spongefish-dsfs`) — `NargSecurity`, the sponge terms.
- `crates/argus-examples/src/bin/schnorr.rs` — a complete, tested profile.

Shorter companion docs: `overview.md`, `rbr-and-sr.md`, `dsfs-bounds.md`,
`instance-aware-security.md`.

The underlying theory (you do **not** need it to use the feature):

- Chiesa & Yogev, *Building Cryptographic Proofs from Hash Functions* (2024) —
  Ch. 12 (state restoration), Ch. 31 (round-by-round), Ch. 32 (preprocessing).
- Chiesa & Orrù, *A Fiat–Shamir Transformation from Duplex Sponges* (ePrint
  2025/536) — the DSFS NARG bounds.
- Canetti, Chen, Holmgren, et al., *Fiat–Shamir from Simpler Assumptions* (2018)
  — the origin of round-by-round soundness.
