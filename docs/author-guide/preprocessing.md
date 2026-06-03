# Preprocessing

Preprocessing splits static relation data from per-proof claims.

Plain Schnorr carries the generator in every instance:

```text
Instance = [G, X]
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

That is a small example. In real indexed protocols, the prover key may be large
and the verifier key may be compact.

## Author Trait

Use `impl_preprocessing_argument!` for keyed arguments. Here is the
preprocessed Schnorr shape from the examples.

First define the key and its committed index:

```rust
#[derive(Clone, Debug)]
struct SchnorrKey<G: CurveGroup>(G);

impl<G: CurveGroup + Encoding> CommittedIndex for SchnorrKey<G> {
    fn committed_index(&self) -> CommittedIndexBytes {
        let mut out = Vec::new();

        // Domain tag for this key commitment. Without the tag, the same bytes
        // could accidentally mean something else in another protocol.
        out.extend_from_slice(b"preprocessed-schnorr:vk:v1");

        // Canonical public encoding of the indexed relation data.
        out.extend_from_slice(self.0.encode().as_ref());

        CommittedIndexBytes::new(out)
    }
}
```

Then write the preprocessing argument:

```rust
ia_core::impl_preprocessing_argument! {
    impl<G> PreprocessingInteractiveArgument for PreprocessedSchnorr<G>
    where
        G: CurveGroup + PrimeGroup + Encoding + Deserialize,
        G::ScalarField: PrimeField + Encoding + Decoding + Deserialize,
    {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            ia_core::pad_protocol_id(b"preprocessed-schnorr")
        }

        // Indexed relation R_G = { (X, x) : X = x * G }.
        type Index = G;

        // This toy example gives both parties the same key shape.
        // In lookup-style protocols, PK and VK are usually different.
        type ProverKey = SchnorrKey<G>;
        type VerifierKey = SchnorrKey<G>;

        // Per-claim data: public key X and secret scalar x.
        type Instance = G;
        type Witness = G::ScalarField;

        fn preprocess(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
            (SchnorrKey(*ix), SchnorrKey(*ix))
        }

        #[allow(non_snake_case)]
        fn prove<P: ProverChannel<Unit = u8>>(
            &self,
            ch: &mut P,
            pk: &SchnorrKey<G>,
            instance: &Self::Instance,
            witness: &Self::Witness,
        ) {
            let G_gen = pk.0;
            let k = G::ScalarField::rand(&mut OsRng);
            let K = G_gen * k;
            ch.send_prover_message(&K);

            let c: G::ScalarField = ch.read_verifier_message();
            let r = k + c * witness;
            ch.send_prover_message(&r);
        }

        #[allow(non_snake_case)]
        fn verify<V: VerifierChannel<Unit = u8>>(
            &self,
            ch: &mut V,
            vk: &SchnorrKey<G>,
            instance: &Self::Instance,
        ) -> VerificationResult<()> {
            let G_gen = vk.0;
            let X = *instance;

            let K: G = ch.read_prover_message()?;
            let c: G::ScalarField = ch.send_verifier_message();
            let r: G::ScalarField = ch.read_prover_message()?;

            if G_gen * r == K + X * c {
                Ok(())
            } else {
                Err(VerificationError)
            }
        }
    }
}
```

The important difference from plain Schnorr is not the message flow. The message
flow is the same. The difference is where `G` lives: the plain protocol carries
`G` in every instance, while the preprocessing protocol receives it through
`pk` or `vk`.

Preprocessing reductions use `impl_preprocessing_reduction!` and return target
instances in the same way plain reductions do.

## Committed Index

Both key types must implement `CommittedIndex`. In the Schnorr example, the same
`SchnorrKey` type is used for both sides, so the implementation above covers
both. In an asymmetric protocol, the implementations usually share a helper:

```rust
fn lookup_committed_index(root: &[u8; 32], n: u32) -> CommittedIndexBytes {
    let mut out = Vec::new();
    out.extend_from_slice(b"preprocessed-lookup:vk:v1");
    out.extend_from_slice(root);
    out.extend_from_slice(&n.to_le_bytes());
    CommittedIndexBytes::new(out)
}

impl CommittedIndex for LookupVerifierKey {
    fn committed_index(&self) -> CommittedIndexBytes {
        lookup_committed_index(&self.root, self.n)
    }
}

impl CommittedIndex for LookupProverKey {
    fn committed_index(&self) -> CommittedIndexBytes {
        let root = *self.tree.root().as_bytes();
        let n = u32::try_from(self.table.len()).expect("table size fits in u32");
        lookup_committed_index(&root, n)
    }
}
```

The committed index is public transcript input. It binds the proof to the
indexed relation before the first challenge. For lookup, that means the proof is
bound to `(root, n)` before the row opening challenge flow begins.

The provided `preprocess_checked(&ix)` helper calls `preprocess(&ix)` and
debug-asserts:

```rust
pk.committed_index() == vk.committed_index()
```

DSFS runs preprocessing through this helper.

## Compile with DSFS

Preprocessing DSFS wrappers are stateless. They do not store keys.

```rust
use ia_core::{PreprocessingCore, PreprocessingNonInteractiveArgument};
use spongefish_dsfs as dsfs;

let pnia = dsfs::preprocessing_non_interactive_argument(
    MyProtocol,
    dsfs::Keccak::default(),
);

let (pk, vk) = pnia.preprocess(&index);

let proof = pnia.prove(&pk, &session, &instance, &witness);
pnia.verify(&vk, &session, &instance, &proof)?;
```

The prover side binds `pk.committed_index()`. The verifier side binds
`vk.committed_index()`. If they differ, the transcripts diverge and verification
fails.

## Key Asymmetry

Preprocessed lookup is the canonical example:

```text
Index       = Vec<u32>
ProverKey   = table + Merkle tree
VerifierKey = root + length
Instance    = (i, claimed_value)
Witness     = ()
```

The prover key is large because it must open paths. The verifier key is small
because it only needs to check paths against the root.

The protocol body still uses channels. The Merkle root is not manually absorbed
by the protocol; it is exposed through `CommittedIndex` and bound by the backend.

## When To Use Preprocessing

Use preprocessing when:

- Many proofs share the same static relation data.
- The verifier should keep a compact key.
- The prover needs derived material such as tables, trees, bases, or oracles.
- The transcript must bind an indexed relation separately from the per-claim
  instance.

Keep a protocol plain when setup would only move fields around without changing
the cost model or relation structure.
