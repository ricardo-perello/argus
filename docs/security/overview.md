# Security Overview

> New to this? Start with [Argus Security, From Scratch](explainer.md) — a
> guided tour of the soundness games and theorems that the docs below assume.

Argus separates two concerns:

- executing a protocol through a backend,
- recording the formal error profile associated with that protocol.

Execution lives in the protocol and channel traits. Security metadata lives in
the `ArgumentSecurity`, `ReductionSecurity`, and preprocessing security traits.
DSFS security helpers consume that metadata together with sponge parameters.

## Transcript Safety

The most important security boundary is transcript ownership. Protocol code
does not absorb public inputs, derive Fiat-Shamir challenges, or inspect proof
bytes. Those operations belong to the backend.

See [Transcript Invariants](transcript-invariants.md) for the review checklist.

## Domain Separation

Every compiled proof must bind the actual protocol being executed. If a protocol
object carries configuration in `self`, and that configuration affects message
flow, challenges, accepted statements, proof layout, or transcript semantics,
then it must be reflected in `protocol_id(&self)` or otherwise bound as public
input before the first challenge.

This is different from transcript state. A protocol object may carry immutable
configuration such as rates, dimensions, code parameters, or mode flags. It must
not carry mutable sponge state, challenge counters, or hidden transcript data.

See [Domain Separation](domain-separation.md).

## Instance-Aware Profiles

Many protocols do not have one global error bound. Soundness may depend on
number of variables, field size, code length, constraint count, degree bounds,
or list-size parameters.

The security API therefore asks for profiles from:

- a concrete instance, or
- an explicit worst-case bound for a family of instances.

Constant-error protocols use `()` for both parameter and bound types.

## DSFS Bounds

The DSFS backend converts an interactive security profile into NARG bounds by
combining:

- SR soundness or knowledge soundness derived from RBR vectors,
- sponge parameters,
- challenge lengths,
- adversarial query budget.

See [DSFS Bounds](dsfs-bounds.md).
