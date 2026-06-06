# Preprocessing

Preprocessing separates static relation data from per-claim data.

Plain Schnorr carries the generator in every instance:

```text
Instance = (G, X)
Witness  = x
```

Preprocessed Schnorr moves `G` into setup:

```text
Index    = G
PK       = key containing G
VK       = key containing G
Instance = X
Witness  = x
```

The message flow is unchanged. The difference is where static data lives.

## Keys Are Inputs

Preprocessing protocols expose setup through `PreprocessingCore`:

```text
preprocess(index) -> (prover_key, verifier_key)
```

Execution remains keyed:

```text
prove(ch, prover_key, instance, witness)
verify(ch, verifier_key, instance)
```

The compiled DSFS wrapper stores the protocol body and sponge configuration, but
it stores no keys:

```rust
use ia_core::prelude::*;   // PreprocessingCore (preprocess) + the keyed role half-traits
use spongefish_dsfs as dsfs;

let pnia = dsfs::preprocessing_non_interactive_argument(
    MyProtocol,
    dsfs::Keccak::default(),
);

let (pk, vk) = pnia.preprocess(&index);
let proof = pnia.prove(&pk, &session, &instance, &witness);
pnia.verify(&vk, &session, &instance, &proof)?;
```

This is intentional. A prover receives the prover key; a verifier receives the
verifier key. The protocol object itself is not a hidden store of setup
material.

## Committed Index

Both key types implement `CommittedIndex`:

```rust
pub trait CommittedIndex {
    fn committed_index(&self) -> CommittedIndexBytes;
}
```

For keys produced by the same preprocessing call, the committed-index bytes must
match:

```text
pk.committed_index() == vk.committed_index()
```

DSFS binds those bytes as public input before the first challenge. This lets a
proof be tied to the indexed relation without requiring the verifier to hold the
whole prover key or requiring protocol code to manually absorb setup data.

The provided `preprocess_checked(&ix)` helper calls `preprocess(&ix)` and
debug-asserts that the two committed indexes agree. Backends use this helper
when they run preprocessing.

## Asymmetric Keys

Lookup-style protocols show why preprocessing is useful:

```text
Index       = table T
ProverKey   = T plus Merkle tree
VerifierKey = Merkle root plus table length
Instance    = (row, claimed value)
Witness     = ()
```

The prover key is large because it needs opening material. The verifier key is
small because it only needs to check openings against the root. Both keys can
derive the same committed-index bytes, usually through one shared helper.

```rust
fn lookup_committed_index(root: &[u8; 32], n: u32) -> CommittedIndexBytes {
    let mut out = Vec::new();
    out.extend_from_slice(b"preprocessed-lookup:vk:v1");
    out.extend_from_slice(root);
    out.extend_from_slice(&n.to_le_bytes());
    CommittedIndexBytes::new(out)
}
```

The protocol body still sends and receives typed messages through the channel.
It does not absorb the Merkle root itself.

## When To Use Preprocessing

Use preprocessing when:

- many proofs share the same static relation data,
- the verifier should keep a compact key,
- the prover needs derived material such as tables, trees, bases, or oracles,
- the transcript must bind an indexed relation separately from the per-claim
  instance.

Keep a protocol plain when setup would only move fields around without changing
the relation structure or cost model.
