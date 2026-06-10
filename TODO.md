# Roadmap

The role-first IA/IR interfaces, DSFS backend, live execution, protocol
examples, sigma compatibility bridge, and WARP integration are implemented.
Current work is stabilization rather than another interface redesign.

## Near Term

- Complete review and upstream integration of the role-first changes.
- Move Argus to its eventual `arkworks-rs` repository.
- Repoint `ark-codes` after its arkworks 0.6 support lands upstream.
- Keep examples, mdBook documentation, and strict API documentation in sync.

## Research Follow-Ups

- Express IBCS as an Argus interactive argument and compile it through DSFS.
- Tighten conservative WARP and Bulletproof security bounds where the analysis
  is available.
- Explore recursive or algebraic channel backends without exposing transcript
  internals to protocol implementations.

Historical implementation plans and completed interface iterations live under
`docs/history/`.
