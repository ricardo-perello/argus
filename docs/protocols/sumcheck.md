# Sumcheck Examples

The sumcheck examples are small protocol demos in `crates/argus-examples`.

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
  `non_interactive_argument`.
- Security metadata whose RBR vector mirrors the round structure.

These examples are useful references when adding a protocol with more than one
public-coin round.
