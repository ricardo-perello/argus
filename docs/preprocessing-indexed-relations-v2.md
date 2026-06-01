# Preprocessing Indexed Relations v2

**Status:** Current implementation snapshot for preprocessing/indexed relations
in Argus and the patched `spongefish-dsfs` backend.

## Goal

Preprocessing protocols split a relation into:

- `Index`: static problem description, processed once.
- `ProverKey`: prover-side material derived from the index.
- `VerifierKey`: verifier-side material derived from the index.
- per-claim instance and witness types.

Plain protocols keep the ordinary `InteractiveArgument` /
`InteractiveReduction` surface. Protocols with real preprocessing implement the
preprocessing leaves directly, usually through `impl_preprocessing_argument!` or
`impl_preprocessing_reduction!`.

## Core Traits

The implemented trait tree is:

```text
ProtocolCore
├── ArgumentCore
│   ├── InteractiveArgument
│   └── PreprocessingInteractiveArgument
└── ReductionCore
    ├── InteractiveReduction
    └── PreprocessingInteractiveReduction
```

`PreprocessingCore` is the shared setup capability:

```rust
pub trait PreprocessingCore: ProtocolCore {
    type Index;
    type ProverKey: CommittedIndex;
    type VerifierKey: CommittedIndex;

    fn preprocess(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey);

    fn preprocess_checked(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
        /* calls preprocess, then debug-asserts matching committed_index() bytes */
    }
}
```

The method is named as an action: `index` remains the noun for the input type and
variable (`Index`, `ix`), while `preprocess` is the verb.

## Committed Index

Both preprocessing keys implement `CommittedIndex`:

```rust
pub struct CommittedIndexBytes(Vec<u8>);

pub trait CommittedIndex {
    fn committed_index(&self) -> CommittedIndexBytes;
}
```

For keys produced by the same `preprocess(ix)` call:

```rust
pk.committed_index() == vk.committed_index()
```

The backend binds these bytes before the first verifier challenge. The prover
side derives them from `pk`; the verifier side derives them from `vk`. This keeps
the compiled object stateless and prevents a verifier-only value from carrying
prover material.

`CommittedIndexBytes` has a canonical encoding:

```text
u64_le(len(bytes)) || bytes
```

For composed keys `(K1, K2)`, the implementation uses a tagged,
length-delimited pair commitment.

## Indexed Public Input

The backend binds preprocessing material and the ordinary instance as one public
input:

```rust
IndexedInstanceRef::new(&committed_index, instance)
```

Both the owned `IndexedInstance<I>` and borrowed `IndexedInstanceRef<'_, I>`
encode as:

```text
b"argus:indexed-instance:v1"
    || committed_index.encode()
    || u64_le(len(instance.encode()))
    || instance.encode()
```

Protocol code does not construct or absorb this value. It is backend-owned
transcript input.

## Authoring Surface

Preprocessing arguments:

```rust
ia_core::impl_preprocessing_argument! {
    impl PreprocessingInteractiveArgument for MyArgument {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            ia_core::pad_protocol_id(b"my-argument")
        }

        type Instance = MyInstance;
        type Witness = MyWitness;
        type Index = MyIndex;
        type ProverKey = MyProverKey;
        type VerifierKey = MyVerifierKey;

        fn preprocess(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
            /* deterministic setup */
        }

        fn prove<P: ProverChannel<Unit = u8>>(
            &self,
            ch: &mut P,
            pk: &Self::ProverKey,
            instance: &Self::Instance,
            witness: &Self::Witness,
        ) {
            /* channel-only prover logic */
        }

        fn verify<V: VerifierChannel<Unit = u8>>(
            &self,
            ch: &mut V,
            vk: &Self::VerifierKey,
            instance: &Self::Instance,
        ) -> VerificationResult<()> {
            /* channel-only verifier logic */
            Ok(())
        }
    }
}
```

Preprocessing reductions use the same setup surface with source/target instance
and witness types.

## DSFS API

Plain protocols compile to stateless plain NARG wrappers:

```rust
let nia = spongefish_dsfs::plain_non_interactive_argument(body, dsfs::Keccak::default());
let proof = nia.prove(&session, &instance, &witness);
nia.verify(&session, &instance, &proof)?;
```

Preprocessing protocols compile to stateless preprocessing NARG wrappers:

```rust
let pnia = spongefish_dsfs::preprocessing_non_interactive_argument(body, dsfs::Keccak::default());
let (pk, vk) = pnia.preprocess(&ix);

let proof = pnia.prove(&pk, &session, &instance, &witness);
pnia.verify(&vk, &session, &instance, &proof)?;
```

For reductions:

```rust
let pnir = spongefish_dsfs::preprocessing_non_interactive_reduction(body, dsfs::Keccak::default());
let (pk, vk) = pnir.preprocess(&ix);

let (proof, target, target_witness) = pnir.prove(&pk, &session, &source, &witness);
let verified_target = pnir.verify(&vk, &session, &source, &proof)?;
```

The concrete backend types are `PreprocessedDsfsArgument` and
`PreprocessedDsfsReduction`. They store only the protocol body and sponge; they
do not store keys.

Applications that persist preprocessing keys pass those keys directly to
`prove` and `verify`. The optional `Prover`, `Verifier`, `ProverReduction`, and
`VerifierReduction` wrappers are convenience views over `(narg, key)`.

## Transcript Shape

Plain DSFS public input:

```text
DomainSeparator::derive(protocol_id, sponge_info, session)
    .instance(instance)
```

Preprocessing DSFS public input:

```text
DomainSeparator::derive(protocol_id, sponge_info, session)
    .instance(IndexedInstanceRef { committed_index, instance })
```

Then keyed execution receives the bare instance:

```text
body.prove(ch, &pk, instance, witness)
body.verify(ch, &vk, instance)
```

The invariants are unchanged:

- all public inputs are absorbed before the first challenge;
- all prover messages are absorbed before the challenge for their round;
- protocol code never touches transcript internals;
- verification consumes exactly the expected proof bytes.

## Composition

Preprocessing composition exists when both components are preprocessing
protocols:

```rust
type Index = (First::Index, Second::Index);
type ProverKey = (First::ProverKey, Second::ProverKey);
type VerifierKey = (First::VerifierKey, Second::VerifierKey);
```

`ChainedReduction` preprocesses each component index and pairs the keys.
`ReducedArgument` does the same for a preprocessing reduction followed by a
preprocessing argument.

Mixed plain/preprocessing composition is explicit through
`TrivialIndexedArgument` and `TrivialIndexedReduction`. There is no blanket lift
that silently turns plain protocols into preprocessing protocols.

## Security Metadata

Plain protocols use `ArgumentSecurity` and `ReductionSecurity`.

Preprocessing protocols use `PreprocessingArgumentSecurity` and
`PreprocessingReductionSecurity`. These split security information into
index-derived parameters/bounds and per-instance parameters/bounds.

For WARP, code parameters, matrix dimensions, OOD sample counts, and shift-query
counts are index-derived; the accumulated claims are per-instance.

## WARP

WARP is implemented as preprocessing components:

- `WarpIndex`: static relation/config/code/Merkle material.
- `WarpProverKey`: prover-side preprocessed material.
- `WarpVerifierKey`: verifier-side metadata and committed-index bytes.
- `WarpInstance`: per-claim instances and accumulator instances only.
- `WarpReduction`: `PreprocessingInteractiveReduction`.
- `WarpDecider`: `PreprocessingInteractiveArgument`.
- `FullWarp`: first-class preprocessing argument with `Index = WarpIndex`.

The old pattern of smuggling static material through the source instance is gone.
The backend binds the committed index before the first challenge.

## Acceptance Tests

The current focused gates are:

```bash
cargo fmt --check
cargo check
cargo test -p ia-core
cargo test -p argus-examples
cargo test -p warp
```

Run `cargo test -p sigma-bridge --test golden_vectors` when checking external
vector compatibility. At the time of this snapshot, the known baseline failures
are `golden_p256_stdhash`, `golden_bls12381_stdhash`, and
`golden_bls12381_keccak`.
