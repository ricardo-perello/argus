# Documentation History

This directory preserves design history that should remain readable without
requiring Git archaeology.

## Policy

- Stable, current documentation lives in top-level topic directories such as
  `architecture/`, `security/`, `api/`, and `protocols/`.
- Versioned design docs such as `iarg-interface-v1.md` and
  `iarg-interface-v6.md` live here.
- ADRs in `docs/adr/` record decisions that should be easy to cite.
- Historical files can be corrected for broken links, but their original design
  intent should not be rewritten into current-state documentation.

## Current history map

- `interface/` — IA/IR trait and composition design iterations.
- `security/` — security profile refactors and theorem bookkeeping.
- `domain-separation/` — domain-separation redesign notes.
- `backends/` — DSFS ownership and backend integration notes.
- `protocols/` — WARP and sigma-bridge historical notes.

## Interface History

- [IA interface v1](interface/iarg-interface-v1.md)
- [IA interface v2](interface/iarg-interface-v2.md)
- [IA interface v3](interface/iarg-interface-v3.md)
- [IA interface v4](interface/iarg-interface-v4.md)
- [IA interface v5](interface/iarg-interface-v5.md)
- [IA interface v6](interface/iarg-interface-v6.md)
- [Interactive reduction v1](interface/interactive-reduction-v1.md)
- [Interactive reduction v2](interface/interactive-reduction-v2.md)

## Backend and Domain-Separation History

- [DSFS ownership options](backends/dsfs-ownership-options.md)
- [DSFS v2](backends/dsfs-v2.md)
- [Domain-separation refactor summary](domain-separation/domain-sep-refactor-summary.md)
- [Domain-separation April 2026 plan](domain-separation/domain-separation-redesign-2026-04-plan.md)

## Protocol and Security History

- [Examples vs WARP](protocols/examples-vs-warp.md)
- [sigma-bridge v1](protocols/sigma-bridge-v1.md)
- [sigma-bridge v2](protocols/sigma-bridge-v2.md)
- [sigma-bridge v3](protocols/sigma-bridge-v3.md)
- [Security profile RBR refactor](security/security-profile-rbr-refactor.md)
