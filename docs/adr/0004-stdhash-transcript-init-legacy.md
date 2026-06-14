# 0004: StdHash Transcript Init Is Legacy (sigma-bridge compat shim)

## Status

Accepted.

## Context

DSFS initialises a transcript from `(protocol_id, sponge_info, session, instance)`.
Two different `StdHash` (SHAKE128) initialisations exist in the tree:

| path | `StdHash` init | used by |
| --- | --- | --- |
| `DomainSeparator::to_prover` (duplex) | `absorb(domsep) ‖ absorb(instance)` | the DSFS compiler, for *all* sponges |
| `DomainSeparator::std_prover` | `absorb(domsep ‖ SHAKE-rate pad) ‖ absorb(instance)` | σ-proofs SHAKE128 golden vectors |

The padding in the second path comes from `StdHash::from_protocol_id`, which
writes the 64-byte domain tag into a full SHAKE128 rate block before continuing.
It is **legacy spongefish behavior**, not a designed property of DSFS. The DSFS
compiler already uses the duplex path (`to_prover`) for every sponge, so the
legacy `std_prover` padding survived in exactly one place: a `TranscriptSponge`
trait that branched on the sponge type, consumed only by sigma-bridge.

spongefish’s maintainer (Michele Orrù) confirmed the two paths should converge —
`StdHash` will eventually init like the other duplex sponges — but not now.

## Decision

Treat the `StdHash` special-case init as **legacy**, and quarantine it:

- The DSFS compiler keeps using `DomainSeparator::to_prover` for every sponge,
  including `StdHash` (the convergence-aligned path). Its `StdHash` transcripts
  are therefore **intentionally not byte-compatible** with the σ-proofs layout.
- `TranscriptSponge` is removed from the `spongefish-dsfs` public API and moved
  into `sigma-bridge` (its sole consumer) as an explicitly-temporary compat shim.
  Its only load-bearing branch is `StdHash`'s `std_prover`/`std_verifier` init,
  which keeps the σ-proofs golden vectors matching upstream.
- A tripwire test (`sigma-bridge` `transcript.rs`) asserts the two `StdHash`
  inits currently differ. It fails the moment spongefish unifies them.

We do **not** unify now by switching `StdHash` onto `to_prover` and regenerating
the σ-proofs vectors ourselves: spongefish has not fixed the final unified
semantics, so doing it now risks regenerating the vectors twice and diverging
from upstream σ-proofs in the meantime.

## Consequences

- The `spongefish-dsfs` API no longer exposes `TranscriptSponge`; only the DSFS
  compiler API (the `to_prover` path) and the low-level `SpongeProver` /
  `SpongeVerifier` adapters remain public.
- `StdHash` in the DSFS compiler is interop-only and heuristic (its DSFS bounds
  are not the analyzed setting; Keccak is). It is not σ-proofs byte-compatible.
- When spongefish unifies the `StdHash` init with the duplex path, the tripwire
  test flips. The follow-up is then: delete the sigma-bridge `TranscriptSponge`
  shim, switch the σ-proofs `StdHash` path to `to_prover`, and regenerate the
  σ-proofs golden vectors **once**.
