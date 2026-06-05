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

### What would change to absorb field elements (non-byte alphabet)?

Concrete question that came up: a protocol sends an EC point with
`ch.send_prover_message(&point)`, and the DSFS sponge absorbs *bytes*. What if we
wanted the sponge to absorb *field elements* (an algebraic sponge like Poseidon,
`Unit = F`) — e.g. for recursion, where an in-circuit verifier should not pay for
byte decomposition? Which layer changes?

Finding (from reading the code): **the channel is already alphabet-generic, but
the compiler and proof artifact are byte-pinned.** It is not "just swap the
sponge."

- **`ia-core` channel traits — no change.** `type Unit` and
  `Encoding<[Self::Unit]>` / `Decoding<[Self::Unit]>` are already generic over the
  alphabet; the traits never assume bytes.
- **`ia-core` proof artifact — changes.** `NargProof(Vec<u8>)`
  (`noninteractive/proof.rs`, doc'd "Byte-oriented proof artifact") is hard
  byte-typed. A field-native NARG needs this to carry units (or a sibling type).
- **`spongefish-dsfs` channel — already generic.** `SpongeProver<DS>` /
  `SpongeVerifier<DS>` use `type Unit = DS::U` (`channel.rs`). Whoever wrote it
  anticipated non-byte alphabets at the channel layer.
- **`spongefish-dsfs` compiler / params — the main work, byte-pinned.** Three
  `U = u8` pins reject a field sponge at compile time:
  `ByteDuplexSponge: DuplexSpongeInterface<U = u8>` (`compile.rs:28`),
  `TranscriptSponge: DuplexSpongeInterface<U = u8>` (`channel.rs:23`),
  `SpongeInfo: ByteDuplexSponge` (`params.rs:42`); plus the NARG is serialized as
  bytes (`compile.rs:503`, `NargProof::from_bytes(... narg_string().to_vec())`).
  You literally cannot pass a Poseidon (`U = F`) sponge to
  `plain_non_interactive_argument` today.
- **Codecs — need field-targeted impls.** `Encoding<[F]>` for a point ("express
  as field elements") and `Decoding<[F]>` for a challenge ("uniform scalar from
  squeezed field elements"). Today the ark codecs target `[u8]`.
- **An actual algebraic sponge.** `Keccak` and `StdHash` are both byte sponges; a
  `DuplexSpongeInterface<U = F>` (Poseidon-style) is needed.
- **Protocol code — one line.** `ProverChannel<Unit = u8>` becomes `Unit = F` (or
  generic); the send/read *body* is unchanged. That portability is the payoff.

Notes for the report:

- The abstraction is **half-plumbed** for field units: the channel layer is
  generic, the compiler / NARG artifact / sponge-params / codecs are byte-
  specialized. This is the concrete content behind the open
  "should `ia-core` own a smaller codec abstraction?" bullet above — a non-byte
  backend forces the codec + `NargProof` genericization.
- **Live mode is nearly free; DSFS is the work.** Interactive execution has no
  NARG to serialize, so the byte assumption is concentrated in the non-interactive
  path — which is unfortunate, since the recursion motivation is specifically
  about the *non-interactive* proof being field-native.
- **Cycle-of-curves subtlety:** "express an EC point as field elements" only
  typechecks when the point's coordinate field aligns with the sponge field `F`.
  That alignment is cryptographic content the `Encoding<[F]>` impl encodes, not a
  free serialization choice.

(Line numbers are against the pinned `ricardo-perello/spongefish` checkout and may
drift; the load-bearing identifiers are the trait/type names.)

## Public-Coin Branching After Commitments

Question:z

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
