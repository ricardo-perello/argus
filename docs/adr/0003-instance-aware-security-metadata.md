# 0003: Instance-Aware Security Metadata

## Status

Accepted.

## Context

Protocol-only security metadata is too coarse for protocols whose soundness
depends on the statement. WARP, sumcheck-style protocols, and code-based
reductions may depend on instance-derived quantities such as code length,
constraint count, degree bounds, or list-size bounds.

Sequential composition also needs a way to evaluate the next component before a
concrete intermediate target instance is known.

## Decision

Replace protocol-only security metadata with instance-aware traits:

- `ArgumentSecurity`,
- `ReductionSecurity`.

Each trait distinguishes concrete-instance parameters from worst-case bounds.
Reductions additionally expose a target bound so composition can evaluate the
next protocol on the intermediate instance family.

## Consequences

- Callers must provide either a concrete instance or an explicit bound.
- Constant-error protocols use `()` params and bounds.
- Composition can derive security profiles without executing the protocol just
  to obtain an intermediate instance.
- The public API is breaking, but the protocol execution and transcript behavior
  are unchanged.
