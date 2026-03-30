# sigma-bridge

Turns any `SigmaProtocol` (from `sigma-proofs`) into a non-interactive proof
through the Argus **DSFS** pipeline (`ia-core` channels backed by `dsfs::SpongeProver` / `SpongeVerifier`).

## Design

- **Pure IA pipeline**: commitments and responses are sent via `send_prover_message`
  (absorb **and** append into the NARG string). The proof is the full spongefish NARG string.
- **Batchable only**: compact proofs are not supported (per project direction).
- **Sponge-generic**: defaults to Keccak; pass `dsfs::StdHash` for SHAKE128.
- **Not byte-identical to `sigma-proofs::Nizk`**: `Nizk::prove_batchable` uses `public_message`
  (absorb-only) for commitments and manually assembles the proof. This crate instead drives
  everything through `ProverChannel::send_prover_message`, yielding different NARG bytes but
  the same cryptographic guarantees.

## Tests

- `tests/curve25519_roundtrip.rs` — prove/verify round-trips on Ristretto (StdHash and Keccak).
- `tests/golden_vectors.rs` — round-trip prove/verify using σ-proofs `CanonicalLinearRelation`
  instances parsed from spec vector JSON files (BLS12-381; P-256 ignored pending upstream fix).
