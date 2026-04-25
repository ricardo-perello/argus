# 0002: Preserve Round-by-Round Security Profiles

## Status

Accepted.

## Context

DSFS security analysis uses state-restoration style bounds derived from
round-by-round soundness behavior. A single flattened protocol error loses the
per-round structure needed for these conversions and for sequential composition.

## Decision

`SecurityProfile` stores vectors of per-round RBR soundness and RBR knowledge
soundness errors. SR errors are derived from these vectors when needed.

Sequential composition concatenates the RBR vectors and composes the other error
terms additively.

## Consequences

- Security metadata remains close to the theorem statements.
- Protocols with heterogeneous round errors can represent them directly.
- Composition can preserve round structure instead of hiding it behind one
  aggregate number.
