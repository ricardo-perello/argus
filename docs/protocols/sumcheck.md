# Sumcheck

The sumcheck examples demonstrate a multi-round public-coin argument.

The plain example is intentionally small: the full evaluation table is public,
the witness is `()`, and the protocol focuses on the repeated round shape:

```text
prover sends round polynomial
verifier sends challenge
prover folds to the next round
```

Run the plain example:

```bash
cargo run -p argus-examples --bin sumcheck
```

Run the committed variant:

```bash
cargo run -p argus-examples --bin sumcheck_commit
```

## What They Demonstrate

- several public-coin rounds through the same channel API,
- prover-message absorption before each challenge in DSFS,
- verifier-side rejection on inconsistent round claims,
- a committed variant that adds Merkle openings around the same sumcheck shape.

Use these examples when adding a protocol with more than one challenge round.
