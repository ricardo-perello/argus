# `sigma-bridge`

`sigma-bridge` is a compatibility experiment. It drives selected
`sigma-proofs` protocols through the Argus channel model and DSFS backend while
preserving external proof-layout expectations where required.

This is not the central contribution of Argus. It is useful because it stresses
the abstraction against an existing proof layout rather than only against toy
protocols.

## Compatibility Concerns

The bridge is responsible for:

- matching external transcript layouts where required,
- preserving selected `sigma-proofs` vector behavior,
- deriving session IDs in the expected format,
- selecting `StdHash` only for explicit compatibility paths.

## Sponge Choice

Argus standard DSFS uses Keccak.

Some `sigma-proofs` compatibility tests use spongefish `StdHash`, which is
SHAKE128. Do not treat this as the Argus default.

## Session Derivation

`sigma_bridge::derive_session_id` uses SHAKE128 with domain
`fiat-shamir/session-id` and writes output into the high 32 bytes of a 64-byte
session field.

This is intentional for compatibility and should not be simplified.

## Tests

The Shake128 `sigma-proofs` fixtures are byte-for-byte golden tests in
`crates/sigma-bridge/tests/golden_vectors.rs` when using `StdHash`.

Some fixture names mention Keccak even when the compatibility path is exercising
an external protocol tag with the `StdHash` transcript. Do not infer the active
sponge from a fixture filename alone.
