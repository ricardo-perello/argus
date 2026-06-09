# Preprocessing

Preprocessing separates static relation data from per-claim data.

For example, a preprocessed Schnorr-style relation may use:

```text
Index    = generator G
PK       = prover key containing G
VK       = verifier key containing G
Instance = public key X
Witness  = secret x
```

The message flow is unchanged. The difference is where static data lives.

## Three Independent Roles

A preprocessing protocol has an indexer plus two executable roles:

```text
indexer.preprocess(index) -> (prover_key, verifier_key)
prover.prove(channel, prover_key, instance, witness)
verifier.verify(channel, verifier_key, instance)
```

When all three roles share their generic bounds, author them together:

```rust,ignore
ia_core::impl_preprocessing_argument! {
    impl {
        indexer: MyIndexer,
        prover: MyProver,
        verifier: MyVerifier,
    }
    {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            ia_core::pad_protocol_id(b"my-preprocessed-protocol")
        }

        type Instance = MyInstance;
        type Witness = MyWitness;
        type Index = MyIndex;
        type ProverKey = MyProverKey;
        type VerifierKey = MyVerifierKey;

        fn preprocess(
            &self,
            index: &Self::Index,
        ) -> (Self::ProverKey, Self::VerifierKey) {
            /* derive matching keys */
        }

        fn prove<C: ProverChannel<Unit = u8>>(/* ... */) { /* ... */ }
        fn verify<C: VerifierChannel<Unit = u8>>(/* ... */)
            -> VerificationResult<()> { /* ... */ }
    }
}
```

The macro emits independent indexer, prover, and verifier implementations.
Role-specific suffix macros remain available when their bounds or source
locations differ.

## Committed-Index Contract

Both key types implement `CommittedIndex`:

```rust,ignore
pub trait CommittedIndex {
    fn committed_index(&self) -> CommittedIndexBytes;
}
```

Indexing is direct:

```rust,ignore
let (pk, vk) = indexer.preprocess(&index);
```

Every `Indexer` implementation must guarantee:

```rust,ignore
pk.committed_index() == vk.committed_index()
```

Argus does not check this contract at runtime. If the commitments differ, the
compiled prover and verifier bind different public inputs and verification
fails. Protocol tests should assert equality for representative indexes.

## DSFS Execution

Indexing stays outside DSFS:

```rust,ignore
let (pk, vk) = indexer.preprocess(&index);

let prover = dsfs::preprocessing_non_interactive_argument_prover(
    MyProver,
    dsfs::Keccak::default(),
);
let verifier = dsfs::preprocessing_non_interactive_argument_verifier(
    MyVerifier,
    dsfs::Keccak::default(),
);

let proof = prover.prove(&pk, &session, &instance, &witness);
verifier.verify(&vk, &session, &instance, &proof)?;
```

DSFS binds `pk.committed_index()` on the proving path and
`vk.committed_index()` on the verification path before the first challenge.
The protocol roles never absorb setup data themselves.

## Asymmetric Keys

Lookup protocols show why the split matters:

```text
Index       = public table
ProverKey   = table plus Merkle tree
VerifierKey = Merkle root plus table length
Instance    = (row, claimed value)
Witness     = ()
```

The prover receives opening material. The verifier receives only what it needs
to check openings. Both keys derive identical committed-index bytes through a
shared canonical encoding.

## Security Metadata

Preprocessing security metadata belongs on the indexer:

- `PreprocessingArgumentSecurity`
- `PreprocessingReductionSecurity`

This lets bounds depend on static index shape without granting the indexer any
proving or verification capability.

Use preprocessing when many claims share static data, the prover needs derived
material, the verifier should keep a compact key, or security bounds depend on
setup parameters.
