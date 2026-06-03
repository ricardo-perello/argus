# `sigma-bridge`

`sigma-bridge` drives `sigma-proofs` protocols through the Argus IA-to-DSFS
pipeline.

It is compatibility-oriented. The main concerns are:

- matching external transcript layouts where required,
- preserving `sigma-proofs` vector behavior,
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

The Keccak-named fixture in the same test file is a bridge regression for
`prove_with_protocol_domain`: it uses the fixture's `ciphersuite` as the
explicit 64-byte Fiat-Shamir protocol tag while still running the `StdHash`
compatibility transcript. Do not infer the active sponge from that filename
alone.
