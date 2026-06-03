# Report Notes

Working notes for questions that come up while writing the report. These are not
settled project decisions.

## Channel Typing: `Unit` vs Message Type

Current channel shape:

```rust
pub trait ProverChannel {
    type Unit;

    fn send_prover_message<PM: Encoding<[Self::Unit]> + NargSerialize>(&mut self, msg: &PM);
    fn read_verifier_message<VM: Decoding<[Self::Unit]>>(&mut self) -> VM;
}

pub trait VerifierChannel {
    type Unit;

    fn read_prover_message<PM: Encoding<[Self::Unit]> + Deserialize>(
        &mut self,
    ) -> VerificationResult<PM>;
    fn send_verifier_message<VM: Decoding<[Self::Unit]>>(&mut self) -> VM;
}
```

Question to discuss with Giacomo/Chiesa:

- `PM`/`VM` are the typed messages.
- `Unit` is the channel alphabet those messages encode into.
- Does `NargSerialize` belong on the abstract interactive channel trait, or is
  that too DSFS/NARG-specific?
- Giacomo's suggested shape used `NargDeserialize` on verifier reads; current
  Argus uses `Deserialize`. Should this be normalized, and if so in which
  direction?
- If `Encoding`/`Decoding` are re-exported from spongefish, is that fine as
  shared codec vocabulary, or should `ia-core` own a smaller codec abstraction?

## Public-Coin Branching After Commitments

Question:

> Is it always correct to say that the verifier just reads a commitment and the
> backend handles absorption before the challenge?

Likely answer:

- The verifier may inspect a prover message and branch before requesting the
  next public coin.
- This is still public-coin if the branch and challenge type/distribution are a
  deterministic public function of the instance and transcript so far.
- It is not compatible with the Argus/DSFS story if the verifier challenge
  depends on hidden verifier state, or if protocol code performs manual
  transcript operations to derive the challenge.

Need to decide how prominently to state this in the report.

## `CommittedIndex` and `preprocess_checked`

Current design:

```rust
let prover_commit = pk.committed_index();
let verifier_commit = vk.committed_index();
assert_eq!(prover_commit, verifier_commit);
```

`PreprocessingCore::preprocess_checked(&ix)` is the helper used by compiled
backends. It calls `preprocess(&ix)` and `debug_assert`s that the two derived
keys agree on `committed_index()`.

Question for Chiesa:

- Is `CommittedIndex` on both keys the cleanest way to express that prover and
  verifier bind the same indexed relation without requiring the prover to hold
  `vk`?
- Is the debug assertion enough as an author-error guard, or should any path
  make the equality check explicit/fallible?
- How should the report phrase the distinction between the mathematical index
  `i`, the verifier key `vk_i`, and the committed index bytes bound into DSFS?

## Indexed Public Input Explanation

Current implementation detail:

```text
IndexedInstanceRef { committed_index, instance }
```

encodes the public input absorbed by DSFS for preprocessing protocols:

```text
tag || committed_index.encode()
    || u64_le(len(instance.encode())) || instance.encode()
```

Author-facing explanation should probably avoid leading with this encoding.
Better story:

- A preprocessing proof is public over `(indexed relation, per-claim instance)`.
- The key supplies the committed-index bytes for the indexed relation.
- The caller supplies the ordinary instance.
- DSFS pairs and length-prefixes them internally so transcript replay is
  deterministic and unambiguous.
