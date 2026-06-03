# Sumcheck Examples

The sumcheck examples are small protocol demos in `crates/argus-examples`.
The plain example is intentionally simple: the full evaluation table is public,
the witness is `()`, and the protocol demonstrates the multi-round public-coin
shape without adding commitments or preprocessing.

Run the plain example:

```bash
cargo run -p argus-examples --bin sumcheck
```

Run the committed example:

```bash
cargo run -p argus-examples --bin sumcheck_commit
```

## What They Demonstrate

- Multi-round public-coin channel flow.
- Repeated prover-message absorption before challenge derivation.
- DSFS compilation of a protocol with several challenge rounds through
  `plain_non_interactive_argument`.
- Verifier-side rejection on inconsistent round claims.
- A committed variant that adds Merkle openings around the same sumcheck shape.

These examples are useful references when adding a protocol with more than one
public-coin round.
