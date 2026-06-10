# Argus Examples

These examples are meant to be read in layers. The first six form the main
curriculum for writing a protocol against `ia-core` and running it through
`spongefish-dsfs`. Each file adds one concept on top of the previous one.

Protocol code in these examples should only drive the transcript through the
Argus channel API:

```rust
ch.send_prover_message(&message);
let challenge = ch.read_verifier_message();

let message = ch.read_prover_message()?;
let challenge = ch.send_verifier_message();
```

The DSFS backend owns public-input binding, prover-message absorption,
challenge derivation, deterministic replay, proof bytes, sponge choice, and
domain separation.

## Main Ladder

| Order | Example | Adds |
| --- | --- | --- |
| 1 | `schnorr` | Plain `InteractiveArgument`; also the one live-channel demo via `--live`. |
| 2 | `dleq` | Preprocessing with symmetric prover and verifier keys. |
| 3 | `preprocessed_lookup` | Asymmetric keys: fat prover key, compact verifier key. |
| 4 | `preprocessed_sumcheck` | Preprocessed `InteractiveReduction`, where verification outputs a target instance. |
| 5 | `composition` | Sequential composition with `ChainedReduction` and `ReducedArgument`. |
| 6 | `multiparty_threads` | Native indexer, prover, and verifier roles distributed across separate parties. |

Run them with:

```bash
cargo run -p argus-examples --bin schnorr
cargo run -p argus-examples --bin schnorr -- --live
cargo run -p argus-examples --bin dleq
cargo run -p argus-examples --bin preprocessed_lookup
cargo run -p argus-examples --bin preprocessed_sumcheck
cargo run -p argus-examples --bin composition
cargo run -p argus-examples --bin multiparty_threads
```

## Advanced Showcases

These are still useful, but they are protocol showcases rather than the shortest
path to learning the Argus interface.

| Example | Focus |
| --- | --- |
| `sumcheck` | Warmup sumcheck as a plain `InteractiveArgument`. |
| `sumcheck_commit` | Committed table plus channel-derived query. |
| `bulletproof_ipa` | Bulletproofs IPA as a monolithic interactive argument. |
| `bulletproof_ipa_reduction` | The same IPA shape expressed as repeated reductions. |
| `bulletproof_range` | Range proof built around the shared IPA core. |
| `warp_accumulate` | Small WARP-style accumulator; the full WARP implementation lives in `crates/warp`. |

## Targeted Tests

| Test | Focus |
| --- | --- |
| `tests/asymmetric_compile.rs` | Independently bounded prover-only and verifier-only implementations compiled through DSFS. |

Run the whole example test set with:

```bash
cargo test -p argus-examples
```
