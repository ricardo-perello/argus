# 0001: Backend-Owned Transcripts

## Status

Accepted.

## Context

Argus protocols are written once and executed by multiple backends. If protocol
code can touch transcript internals directly, DSFS ordering, domain separation,
and deterministic replay become local protocol responsibilities.

That would make security review fragile.

## Decision

Protocol code uses only the `ia-core` channel traits.

Transcript mechanics are backend-owned. In particular, sponge operations,
Fiat-Shamir challenge derivation, public-input absorption, salt handling, and
proof byte replay live in `spongefish::dsfs`.

## Consequences

- Protocol code stays backend-agnostic.
- Transcript invariants can be reviewed in one layer.
- Any change to absorb/squeeze order, sponge choice, salt policy, or proof layout
  is a backend change.
- Compatibility paths such as `sigma-bridge` must still go through the backend
  interface unless they are deliberately implementing an external layout.
