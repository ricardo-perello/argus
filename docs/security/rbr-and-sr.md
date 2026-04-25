# RBR and SR Soundness

Argus stores round-by-round security because DSFS security theorems are stated
through state-restoration style bounds derived from per-round behavior.

## RBR Errors

`SecurityProfile::rbr_soundness_errors` stores one error bound per public-coin
round:

```text
[epsilon_1^rbr, ..., epsilon_mu^rbr]
```

`SecurityProfile::rbr_knowledge_soundness_errors` stores the knowledge-soundness
analogue:

```text
[kappa_1^rbr, ..., kappa_mu^rbr]
```

Each entry is a `SecurityErrorBound`, a function of adversarial query budget
`t`.

## SR Derivation

Argus derives SR soundness from the RBR vector using the heterogeneous form:

```text
epsilon^sr(t) <= t * max_i epsilon_i^rbr(t) + sum_i epsilon_i^rbr(t)
```

Knowledge soundness uses the same shape with `kappa_i^rbr`.

This is why keeping the vector matters. Flattening everything into one protocol
error would lose the round structure needed for DSFS bookkeeping and for
composition.

## Composition

Sequential composition concatenates RBR vectors and adds the plain/HVZK error
terms. For reductions, the second component is evaluated on a bound for the
intermediate target instance, not on a concrete target instance.

That detail is the main reason the security API is instance-aware.
