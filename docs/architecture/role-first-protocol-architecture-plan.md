# Role-First Prover, Verifier, and Indexer Architecture Record

**Status:** implemented on `codex/role-first-architecture`

**Decision date:** 2026-06-08

**Implementation date:** 2026-06-09

**Supersedes:** the production architecture proposed by
`docs/history/plans/prover-verifier-split-presentation.md`

This document is the implementation record and migration rationale for the
role-first architecture. Sections that discuss `PreprocessingCore`, role views,
conjunction traits, `CombinedIA`, or `CombinedNarg` describe the superseded
baseline that motivated the migration, not the current API. For concise current
usage, see [Protocol Shapes](ia-ir.md), the
[Author Guide](../author-guide/overview.md), and the
[`ia-core` API](../api/ia-core.md).

The implementation replaced the "full protocol body with optional role views"
model with native, independently authored prover, verifier, and indexer roles.

The production abstraction is no longer one value that contains every algorithm.
Instead:

```text
native prover body   -> DSFS -> non-interactive prover
native verifier body -> DSFS -> non-interactive verifier
native indexer       -> prover key + verifier key
```

The three roles may:

- live in different crates,
- have different dependencies,
- have different configuration,
- be compiled into different binaries, and
- run on different machines.

They agree only on the public proof format: protocol identity, public instance
types, key types where applicable, transcript parameters selected by the backend,
and canonical encodings.

This is an API and dependency-boundary refactor. It must not change DSFS transcript
ordering, sponge behavior, domain-separation inputs, proof serialization, or proof
bytes.

The five approaches discussed in the previous presentation are resolved as:

| Approach | Decision |
|---|---|
| 1. Full body compiled to full NARG | Remove from the production API. |
| 2. Full body narrowed through `into_prover` / `into_verifier` | Remove from the production API. |
| 3. Native one-sided bodies compiled independently | Make this the only baseline path. |
| 4. Combine one-sided interactive bodies | Defer until approach 3 is complete and justified by a concrete R&D use. |
| 5. Combine one-sided compiled NARGs | Defer until approach 3 is complete and justified by a concrete R&D use. |

---

## 1. Proposed Trait Tree

The trait hierarchy becomes role-first. Prover-only data is moved below prover
cores, while verifier cores contain only public statement types.

```text
ProtocolCore
|   fn protocol_id(...)
|
+-- ArgumentCore
|   |   type Instance
|   |
|   +-- ArgumentProverCore
|   |   |   type Witness
|   |   |
|   |   +-- InteractiveArgumentProver
|   |   +-- PreprocessingInteractiveArgumentProver
|   |   +-- NonInteractiveArgumentProver
|   |   `-- PreprocessingNonInteractiveArgumentProver
|   |
|   +-- InteractiveArgumentVerifier
|   +-- PreprocessingInteractiveArgumentVerifier
|   +-- NonInteractiveArgumentVerifier
|   `-- PreprocessingNonInteractiveArgumentVerifier
|
+-- ReductionCore
|   |   type SourceInstance
|   |   type TargetInstance
|   |
|   +-- ReductionProverCore
|   |   |   type SourceWitness
|   |   |   type TargetWitness
|   |   |
|   |   +-- InteractiveReductionProver
|   |   +-- PreprocessingInteractiveReductionProver
|   |   +-- NonInteractiveReductionProver
|   |   `-- PreprocessingNonInteractiveReductionProver
|   |
|   +-- InteractiveReductionVerifier
|   +-- PreprocessingInteractiveReductionVerifier
|   +-- NonInteractiveReductionVerifier
|   `-- PreprocessingNonInteractiveReductionVerifier
|
`-- Indexer
    type Index
    type ProverKey
    type VerifierKey
    fn preprocess(...)
```

`NonInteractiveSession` remains an orthogonal capability used by each compiled
non-interactive role:

```rust
pub trait NonInteractiveSession: ProtocolCore {
    type Session;
}
```

There are intentionally no final "full protocol" conjunction traits.

### 1.1 Core traits

```rust
pub trait ProtocolCore {
    fn protocol_id(&self) -> impl AsRef<[u8]>;
}

pub trait ArgumentCore: ProtocolCore {
    type Instance;
}

pub trait ArgumentProverCore: ArgumentCore {
    type Witness;
}

pub trait ReductionCore: ProtocolCore {
    type SourceInstance;
    type TargetInstance;
}

pub trait ReductionProverCore: ReductionCore {
    type SourceWitness;
    type TargetWitness;
}
```

The important change is that witnesses no longer appear on `ArgumentCore` or
`ReductionCore`. A verifier implementation therefore does not need to name, import,
or compile prover-only witness types.

### 1.2 Plain interactive arguments

```rust
pub trait InteractiveArgumentProver: ArgumentProverCore {
    fn prove<C: ProverChannel<Unit = u8>>(
        &self,
        channel: &mut C,
        instance: &Self::Instance,
        witness: &Self::Witness,
    );
}

pub trait InteractiveArgumentVerifier: ArgumentCore {
    fn verify<C: VerifierChannel<Unit = u8>>(
        &self,
        channel: &mut C,
        instance: &Self::Instance,
    ) -> VerificationResult<()>;
}
```

### 1.3 Preprocessing interactive arguments

Each executable role names only the key it receives.

```rust
pub trait PreprocessingInteractiveArgumentProver: ArgumentProverCore {
    type ProverKey: CommittedIndex;

    fn prove<C: ProverChannel<Unit = u8>>(
        &self,
        channel: &mut C,
        prover_key: &Self::ProverKey,
        instance: &Self::Instance,
        witness: &Self::Witness,
    );
}

pub trait PreprocessingInteractiveArgumentVerifier: ArgumentCore {
    type VerifierKey: CommittedIndex;

    fn verify<C: VerifierChannel<Unit = u8>>(
        &self,
        channel: &mut C,
        verifier_key: &Self::VerifierKey,
        instance: &Self::Instance,
    ) -> VerificationResult<()>;
}
```

The prover does not name `VerifierKey`. The verifier does not name `ProverKey` or
`Witness`.

### 1.4 Plain interactive reductions

```rust
pub trait InteractiveReductionProver: ReductionProverCore {
    fn prove<C: ProverChannel<Unit = u8>>(
        &self,
        channel: &mut C,
        source_instance: &Self::SourceInstance,
        source_witness: &Self::SourceWitness,
    ) -> (Self::TargetInstance, Self::TargetWitness);
}

pub trait InteractiveReductionVerifier: ReductionCore {
    fn verify<C: VerifierChannel<Unit = u8>>(
        &self,
        channel: &mut C,
        source_instance: &Self::SourceInstance,
    ) -> VerificationResult<Self::TargetInstance>;
}
```

### 1.5 Preprocessing interactive reductions

```rust
pub trait PreprocessingInteractiveReductionProver: ReductionProverCore {
    type ProverKey: CommittedIndex;

    fn prove<C: ProverChannel<Unit = u8>>(
        &self,
        channel: &mut C,
        prover_key: &Self::ProverKey,
        source_instance: &Self::SourceInstance,
        source_witness: &Self::SourceWitness,
    ) -> (Self::TargetInstance, Self::TargetWitness);
}

pub trait PreprocessingInteractiveReductionVerifier: ReductionCore {
    type VerifierKey: CommittedIndex;

    fn verify<C: VerifierChannel<Unit = u8>>(
        &self,
        channel: &mut C,
        verifier_key: &Self::VerifierKey,
        source_instance: &Self::SourceInstance,
    ) -> VerificationResult<Self::TargetInstance>;
}
```

### 1.6 Non-interactive output traits

The non-interactive vocabulary follows the same split. There are no full
`NonInteractiveArgument` or `NonInteractiveReduction` conjunction traits.

```rust
pub trait NonInteractiveArgumentProver:
    ArgumentProverCore + NonInteractiveSession
{
    fn prove(
        &self,
        session: &Self::Session,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> NargProof;
}

pub trait NonInteractiveArgumentVerifier:
    ArgumentCore + NonInteractiveSession
{
    fn verify(
        &self,
        session: &Self::Session,
        instance: &Self::Instance,
        proof: &NargProof,
    ) -> VerificationResult<()>;
}
```

Preprocessing non-interactive traits similarly carry only their own key:

```rust
pub trait PreprocessingNonInteractiveArgumentProver:
    ArgumentProverCore + NonInteractiveSession
{
    type ProverKey: CommittedIndex;

    fn prove(
        &self,
        prover_key: &Self::ProverKey,
        session: &Self::Session,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> NargProof;
}

pub trait PreprocessingNonInteractiveArgumentVerifier:
    ArgumentCore + NonInteractiveSession
{
    type VerifierKey: CommittedIndex;

    fn verify(
        &self,
        verifier_key: &Self::VerifierKey,
        session: &Self::Session,
        instance: &Self::Instance,
        proof: &NargProof,
    ) -> VerificationResult<()>;
}
```

The two non-interactive reduction pairs mirror these signatures, replacing
argument inputs and outputs with reduction inputs and outputs.

---

## 2. The Indexer Is a Separate Production Role

The current `PreprocessingCore` is implemented on the same body as proving and
verification. It exposes the indexer algorithm and both key types to every role.
That is incompatible with separate deployment and with role-specific
configuration.

Replace it with an independent `Indexer` trait:

```rust
pub trait Indexer: ProtocolCore {
    type Index;
    type ProverKey: CommittedIndex;
    type VerifierKey: CommittedIndex;

    fn preprocess(
        &self,
        index: &Self::Index,
    ) -> (Self::ProverKey, Self::VerifierKey);
}
```

The `Indexer` contract requires every returned key pair to satisfy
`pk.committed_index() == vk.committed_index()`. Argus does not check this at
runtime. A violation produces incompatible prover and verifier transcripts and
therefore causes verification failure.

The indexer:

- owns setup-specific configuration,
- knows both output key types,
- emits the prover key for the prover machine,
- emits the verifier key for the verifier machine,
- checks that both keys commit to the same indexed relation, and
- contains no proving or verification algorithm.

The prover:

- receives only `ProverKey`,
- derives `pk.committed_index()` through the DSFS backend, and
- never needs the verifier key or indexer implementation.

The verifier:

- receives only `VerifierKey`,
- derives `vk.committed_index()` through the DSFS backend, and
- never needs the prover key, witness type, or indexer implementation.

### 2.1 Compatibility across independently authored roles

There is deliberately no combined object that performs this wiring. Integration
code and tests express compatibility directly:

```rust
fn assert_argument_roles_match<I, P, V>(indexer: &I, prover: &P, verifier: &V)
where
    I: Indexer<
        ProverKey = P::ProverKey,
        VerifierKey = V::VerifierKey,
    >,
    P: PreprocessingInteractiveArgumentProver,
    V: PreprocessingInteractiveArgumentVerifier<Instance = P::Instance>,
{
    assert_eq!(
        indexer.protocol_id().as_ref(),
        prover.protocol_id().as_ref(),
    );
    assert_eq!(
        prover.protocol_id().as_ref(),
        verifier.protocol_id().as_ref(),
    );
}
```

Associated-type equality checks key and public instance compatibility. Matching
`protocol_id` checks proof-format identity at integration time.

This helper is for tests, examples, and deployment validation. It does not create
a new full-protocol production type.

### 2.2 Shared and role-local configuration

Each role may contain a common format descriptor plus unrelated local settings:

```rust
struct LookupFormat {
    table_width: usize,
    rounds: usize,
}

struct LookupIndexer {
    format: LookupFormat,
    storage: IndexStorageConfig,
}

struct LookupProver {
    format: LookupFormat,
    msm: MsmConfig,
}

struct LookupVerifier {
    format: LookupFormat,
    limits: VerificationLimits,
}
```

The common descriptor determines anything that affects proof compatibility.
Role-local settings may change performance or deployment behavior but must not
change transcript layout.

`protocol_id()` must identify the compiled proof format. Any change to sponge
choice, salt policy, transcript layout, or NARG encoding still requires the
existing DSFS-level domain-separation review.

---

## 3. Why This Architecture Changes

### 3.1 Production roles run separately

In production, proving, verification, and indexing will generally happen in
different processes or machines. A single concrete type containing all three
algorithms models neither deployment nor ownership accurately.

### 3.2 Dependency boundaries must be real

`VerifierOnly<FullProtocol>` hides `.prove()` but still contains a type whose
prover implementation was compiled. That is an API boundary, not a dependency
boundary.

Native one-sided bodies allow:

- a verifier crate that does not depend on prover implementation code,
- a recursive prover that embeds an inner verifier without importing the inner
  prover,
- a prover binary that does not contain the verifier implementation, and
- an indexer binary with neither executable protocol role.

### 3.3 Role configuration may differ

The prover, verifier, and indexer can share protocol parameters while requiring
different runtime configuration. One body type forces those settings into one
constructor and one ownership model.

### 3.4 The type system should not expose impossible operations

A verifier type should not implement a trait that mentions witnesses or prover
keys. An indexer type should not expose `prove` or `verify`. This removes hidden
capabilities rather than merely hiding methods.

### 3.5 Production first, R&D adapters later

The core architecture should model deployment correctly. Convenience adapters
for experiments may be added later, but they must be visibly secondary and must
not become the foundation on which DSFS compilation depends.

---

## 4. Traits and Adapters Removed

The following concepts are removed from the production API:

| Current concept | Reason for removal |
|---|---|
| `InteractiveArgument` | Full prover-plus-verifier conjunction is no longer a production role. |
| `InteractiveReduction` | Same for reductions. |
| `PreprocessingInteractiveArgument` | Conflates two executable roles and shared preprocessing. |
| `PreprocessingInteractiveReduction` | Same for preprocessing reductions. |
| `NonInteractiveArgument` | Compiled prover and verifier are separate outputs. |
| `NonInteractiveReduction` | Same for compiled reductions. |
| `PreprocessingNonInteractiveArgument` | Same for compiled preprocessing arguments. |
| `PreprocessingNonInteractiveReduction` | Same for compiled preprocessing reductions. |
| `PreprocessingCore` | Replaced by the independent `Indexer` role. |
| `ProverOnly<T>` / `VerifierOnly<T>` | Hide an opposite capability that still exists in `T`. |
| `IntoProver` / `IntoVerifier` | Approach 2 is no longer supported as the baseline. |
| `CombinedIA` | Approach 4 is deferred; production does not recombine bodies. |
| `CombinedNarg` | Approach 5 is deferred; production does not recombine compiled roles. |

Removing these types also removes the "full body -> DSFS -> prove + verify" path.
DSFS compiles one native role at a time.

---

## 5. Authoring Model

Manual role-specific trait implementations are the semantic API. Macros are an
authoring convenience over those traits.

### 5.1 Native role types

Authors define separate concrete types:

```rust
struct MyProtocolProver {
    common: CommonFormat,
    prover_config: ProverConfig,
}

struct MyProtocolVerifier {
    common: CommonFormat,
    verifier_config: VerifierConfig,
}

struct MyProtocolIndexer {
    common: CommonFormat,
    indexer_config: IndexerConfig,
}
```

No wrapper transforms one of these types into another.

### 5.2 Shared and role-specific macros

The short macro is the normal path when roles share generic bounds:

```rust
ia_core::impl_interactive_argument! {
    impl<G> {
        prover: SchnorrProver<G>,
        verifier: SchnorrVerifier<G>,
    }
    where
        G: CurveGroup,
    {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            schnorr_protocol_id()
        }
        type Instance = SchnorrInstance<G>;
        type Witness = G::ScalarField;
        fn prove<C: ProverChannel<Unit = u8>>(/* ... */) { /* ... */ }
        fn verify<C: VerifierChannel<Unit = u8>>(/* ... */)
            -> VerificationResult<()> { /* ... */ }
    }
}
```

This is source-level dispatch only: it emits native impls for different
concrete types and creates no conjunction trait or runtime wrapper. The same
pattern applies to reductions and to three-role preprocessing protocols.

When roles require different bounds or live in separate crates, use the suffix
forms such as `impl_interactive_argument_prover!`,
`impl_interactive_argument_verifier!`, and the preprocessing
`*_indexer!`/`*_prover!`/`*_verifier!` macros.

### 5.4 Suggested crate layout

For protocols that require strong dependency isolation:

```text
my-protocol-format
|-- public instance types
|-- key serialization types or shared key commitments
`-- protocol-id derivation

my-protocol-prover
|-- prover-only dependencies
`-- native prover role

my-protocol-verifier
|-- verifier-only dependencies
`-- native verifier role

my-protocol-indexer
|-- setup-only dependencies
`-- native indexer role
```

Small examples may keep all three types in one crate. They are still separate
types, but not separate dependency units.

---

## 6. Example: Plain Interactive Argument

This minimal argument proves knowledge of a value equal to the public instance.
It is intentionally simple; the important part is the role separation.

```rust
use ia_core::{
    ProverChannel, VerificationError, VerificationResult, VerifierChannel,
    pad_protocol_id,
};

fn echo_argument_id() -> [u8; 32] {
    pad_protocol_id(b"echo-argument-v1")
}

pub struct EchoProver {
    pub batching: usize,
}

pub struct EchoVerifier {
    pub reject_zero: bool,
}

ia_core::impl_interactive_argument_prover! {
    impl for EchoProver {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            echo_argument_id()
        }

        type Instance = u64;
        type Witness = u64;

        fn prove<C: ProverChannel<Unit = u8>>(
            &self,
            channel: &mut C,
            _instance: &Self::Instance,
            witness: &Self::Witness,
        ) {
            channel.send_prover_message(witness);
        }
    }
}

ia_core::impl_interactive_argument_verifier! {
    impl for EchoVerifier {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            echo_argument_id()
        }

        type Instance = u64;

        fn verify<C: VerifierChannel<Unit = u8>>(
            &self,
            channel: &mut C,
            instance: &Self::Instance,
        ) -> VerificationResult<()> {
            let witness: u64 = channel.read_prover_message()?;
            if witness == *instance && (!self.reject_zero || witness != 0) {
                Ok(())
            } else {
                Err(VerificationError)
            }
        }
    }
}
```

The prover's `batching` configuration and the verifier's `reject_zero`
configuration are independent. In a real protocol, any option that changes the
accepted proof format must be represented in `protocol_id`; local performance
options must not alter transcript behavior.

Live execution runs `EchoProver` and `EchoVerifier` against the paired channel
implementations. DSFS compiles them separately, as described in section 10.

---

## 7. Example: Preprocessing Interactive Argument

The indexer, prover, and verifier are three independent types.

```rust
use ia_core::{
    CommittedIndex, CommittedIndexBytes, ProverChannel, VerificationError,
    VerificationResult, VerifierChannel, pad_protocol_id,
};

fn scaled_argument_id() -> [u8; 32] {
    pad_protocol_id(b"scaled-argument-v1")
}

#[derive(Clone)]
pub struct ScaleProverKey {
    multiplier: u64,
}

#[derive(Clone)]
pub struct ScaleVerifierKey {
    multiplier: u64,
}

fn scale_commitment(multiplier: u64) -> CommittedIndexBytes {
    CommittedIndexBytes::new(multiplier.to_le_bytes().to_vec())
}

impl CommittedIndex for ScaleProverKey {
    fn committed_index(&self) -> CommittedIndexBytes {
        scale_commitment(self.multiplier)
    }
}

impl CommittedIndex for ScaleVerifierKey {
    fn committed_index(&self) -> CommittedIndexBytes {
        scale_commitment(self.multiplier)
    }
}

pub struct ScaleIndexer {
    pub validate_nonzero: bool,
}

pub struct ScaleProver {
    pub parallelism: usize,
}

pub struct ScaleVerifier {
    pub strict: bool,
}

ia_core::impl_preprocessing_argument_indexer! {
    impl for ScaleIndexer {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            scaled_argument_id()
        }

        type Instance = u64;
        type Index = u64;
        type ProverKey = ScaleProverKey;
        type VerifierKey = ScaleVerifierKey;

        fn preprocess(
            &self,
            multiplier: &Self::Index,
        ) -> (Self::ProverKey, Self::VerifierKey) {
            assert!(!self.validate_nonzero || *multiplier != 0);
            (
                ScaleProverKey {
                    multiplier: *multiplier,
                },
                ScaleVerifierKey {
                    multiplier: *multiplier,
                },
            )
        }
    }
}

ia_core::impl_preprocessing_argument_prover! {
    impl for ScaleProver {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            scaled_argument_id()
        }

        type Instance = u64;
        type Witness = u64;
        type ProverKey = ScaleProverKey;

        fn prove<C: ProverChannel<Unit = u8>>(
            &self,
            channel: &mut C,
            prover_key: &Self::ProverKey,
            _instance: &Self::Instance,
            witness: &Self::Witness,
        ) {
            let response = witness * prover_key.multiplier;
            channel.send_prover_message(&response);
        }
    }
}

ia_core::impl_preprocessing_argument_verifier! {
    impl for ScaleVerifier {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            scaled_argument_id()
        }

        type Instance = u64;
        type VerifierKey = ScaleVerifierKey;

        fn verify<C: VerifierChannel<Unit = u8>>(
            &self,
            channel: &mut C,
            verifier_key: &Self::VerifierKey,
            instance: &Self::Instance,
        ) -> VerificationResult<()> {
            let response: u64 = channel.read_prover_message()?;
            let expected = instance * verifier_key.multiplier;
            if response == expected && (!self.strict || verifier_key.multiplier != 0) {
                Ok(())
            } else {
                Err(VerificationError)
            }
        }
    }
}
```

Deployment wiring:

```rust
let (pk, vk) = indexer
    .preprocess(&multiplier)
    .expect("indexer emitted incompatible keys");

// Send `pk` to the prover service and `vk` to the verifier service.
// Neither service needs the `ScaleIndexer` type.
```

The equality of `pk.committed_index()` and `vk.committed_index()` is checked at
the only place that holds both keys: the indexer.

---

## 8. Example: Plain Interactive Reduction

An interactive reduction has distinct source and target public instances. Only
the prover role names source and target witness types.

```rust
use ia_core::{ProverChannel, VerificationResult, VerifierChannel, pad_protocol_id};

fn decrement_reduction_id() -> [u8; 32] {
    pad_protocol_id(b"decrement-reduction-v1")
}

pub struct DecrementProver;
pub struct DecrementVerifier;

ia_core::impl_interactive_reduction_prover! {
    impl for DecrementProver {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            decrement_reduction_id()
        }

        type SourceInstance = u64;
        type TargetInstance = u64;
        type SourceWitness = u64;
        type TargetWitness = u64;

        fn prove<C: ProverChannel<Unit = u8>>(
            &self,
            _channel: &mut C,
            source_instance: &Self::SourceInstance,
            source_witness: &Self::SourceWitness,
        ) -> (Self::TargetInstance, Self::TargetWitness) {
            (source_instance - 1, source_witness - 1)
        }
    }
}

ia_core::impl_interactive_reduction_verifier! {
    impl for DecrementVerifier {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            decrement_reduction_id()
        }

        type SourceInstance = u64;
        type TargetInstance = u64;

        fn verify<C: VerifierChannel<Unit = u8>>(
            &self,
            _channel: &mut C,
            source_instance: &Self::SourceInstance,
        ) -> VerificationResult<Self::TargetInstance> {
            Ok(source_instance - 1)
        }
    }
}
```

The example has no messages or challenges, but it demonstrates the type
boundary: `DecrementVerifier` has no source or target witness associated type.

---

## 9. Example: Preprocessing Interactive Reduction

```rust
use ia_core::{
    CommittedIndex, CommittedIndexBytes, ProverChannel, VerificationResult,
    VerifierChannel, pad_protocol_id,
};

fn offset_reduction_id() -> [u8; 32] {
    pad_protocol_id(b"offset-reduction-v1")
}

#[derive(Clone)]
pub struct OffsetProverKey(u64);

#[derive(Clone)]
pub struct OffsetVerifierKey(u64);

impl CommittedIndex for OffsetProverKey {
    fn committed_index(&self) -> CommittedIndexBytes {
        CommittedIndexBytes::new(self.0.to_le_bytes().to_vec())
    }
}

impl CommittedIndex for OffsetVerifierKey {
    fn committed_index(&self) -> CommittedIndexBytes {
        CommittedIndexBytes::new(self.0.to_le_bytes().to_vec())
    }
}

pub struct OffsetIndexer;
pub struct OffsetProver;
pub struct OffsetVerifier;

ia_core::impl_preprocessing_reduction_indexer! {
    impl for OffsetIndexer {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            offset_reduction_id()
        }

        type SourceInstance = u64;
        type TargetInstance = u64;
        type Index = u64;
        type ProverKey = OffsetProverKey;
        type VerifierKey = OffsetVerifierKey;

        fn preprocess(
            &self,
            offset: &Self::Index,
        ) -> (Self::ProverKey, Self::VerifierKey) {
            (
                OffsetProverKey(*offset),
                OffsetVerifierKey(*offset),
            )
        }
    }
}

ia_core::impl_preprocessing_reduction_prover! {
    impl for OffsetProver {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            offset_reduction_id()
        }

        type SourceInstance = u64;
        type TargetInstance = u64;
        type SourceWitness = u64;
        type TargetWitness = u64;
        type ProverKey = OffsetProverKey;

        fn prove<C: ProverChannel<Unit = u8>>(
            &self,
            _channel: &mut C,
            prover_key: &Self::ProverKey,
            source_instance: &Self::SourceInstance,
            source_witness: &Self::SourceWitness,
        ) -> (Self::TargetInstance, Self::TargetWitness) {
            (
                source_instance + prover_key.0,
                source_witness + prover_key.0,
            )
        }
    }
}

ia_core::impl_preprocessing_reduction_verifier! {
    impl for OffsetVerifier {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            offset_reduction_id()
        }

        type SourceInstance = u64;
        type TargetInstance = u64;
        type VerifierKey = OffsetVerifierKey;

        fn verify<C: VerifierChannel<Unit = u8>>(
            &self,
            _channel: &mut C,
            verifier_key: &Self::VerifierKey,
            source_instance: &Self::SourceInstance,
        ) -> VerificationResult<Self::TargetInstance> {
            Ok(source_instance + verifier_key.0)
        }
    }
}
```

Again, the indexer is the only role that knows both key types. The verifier does
not name either witness type.

---

## 10. DSFS Layer Changes

The DSFS layer changes its public wrapper types and trait bounds. Its transcript
implementation remains shared and unchanged.

### 10.1 Explicit role-specific constructors

Replace the conditionally capable constructors with explicit role constructors:

```rust
plain_non_interactive_argument_prover(body, sponge)
    -> DsfsArgumentProver<P, Session, DS>

plain_non_interactive_argument_verifier(body, sponge)
    -> DsfsArgumentVerifier<V, Session, DS>

plain_non_interactive_reduction_prover(body, sponge)
    -> DsfsReductionProver<P, Session, DS>

plain_non_interactive_reduction_verifier(body, sponge)
    -> DsfsReductionVerifier<V, Session, DS>
```

Preprocessing counterparts:

```rust
preprocessing_non_interactive_argument_prover(body, sponge)
    -> PreprocessedDsfsArgumentProver<P, Session, DS>

preprocessing_non_interactive_argument_verifier(body, sponge)
    -> PreprocessedDsfsArgumentVerifier<V, Session, DS>

preprocessing_non_interactive_reduction_prover(body, sponge)
    -> PreprocessedDsfsReductionProver<P, Session, DS>

preprocessing_non_interactive_reduction_verifier(body, sponge)
    -> PreprocessedDsfsReductionVerifier<V, Session, DS>
```

Salted variants remain available with the same explicit role split.

### 10.2 Plain argument wrappers

```rust
pub struct DsfsArgumentProver<P, S, DS = Keccak, const SALT_LEN: usize = 0> {
    prover: P,
    duplex_sponge: DS,
    _session: PhantomData<S>,
}

pub struct DsfsArgumentVerifier<V, S, DS = Keccak, const SALT_LEN: usize = 0> {
    verifier: V,
    duplex_sponge: DS,
    _session: PhantomData<S>,
}
```

The prover wrapper implements:

- `ProtocolCore`,
- `ArgumentCore`,
- `ArgumentProverCore`,
- `NonInteractiveSession`, and
- `NonInteractiveArgumentProver`.

The verifier wrapper implements:

- `ProtocolCore`,
- `ArgumentCore`,
- `NonInteractiveSession`, and
- `NonInteractiveArgumentVerifier`.

It does not implement `ArgumentProverCore`, so its public type surface contains no
witness type.

### 10.3 Preprocessing wrappers

DSFS does not implement or forward `Indexer`. Indexing is not a DSFS
compilation operation.

The compiled preprocessing prover:

- stores only the native prover body and sponge configuration,
- accepts only `P::ProverKey`,
- obtains `prover_key.committed_index()`, and
- binds it with the public instance before the first challenge.

The compiled preprocessing verifier:

- stores only the native verifier body and sponge configuration,
- accepts only `V::VerifierKey`,
- obtains `verifier_key.committed_index()`, and
- binds it with the public instance before the first challenge.

Usage:

```rust
let (pk, vk) = indexer
    .preprocess(&index)
    .expect("indexer emitted incompatible keys");

let prover = dsfs::preprocessing_non_interactive_argument_prover::<_, Session, _>(
    prover_body,
    dsfs::Keccak::default(),
);

let verifier = dsfs::preprocessing_non_interactive_argument_verifier::<_, Session, _>(
    verifier_body,
    dsfs::Keccak::default(),
);

let proof = prover.prove(&pk, &session, &instance, &witness);
verifier.verify(&vk, &session, &instance, &proof)?;
```

### 10.4 Shared private transcript runners

The current private functions already separate proving and verification:

```text
prove_with_sponge_and_salt
verify_with_sponge_and_salt
prepared_prove_with_sponge_and_salt
prepared_verify_with_sponge_and_salt
prove_reduction_with_sponge_and_salt_full
verify_reduction_with_sponge_and_salt
prepared_prove_reduction_with_sponge_and_salt
prepared_verify_reduction_with_sponge_and_salt
```

Keep one copy of each transcript runner. Change only their trait bounds:

```rust
P: InteractiveArgumentProver
V: InteractiveArgumentVerifier
```

and the corresponding preprocessing/reduction role traits.

Do not copy transcript initialization, absorption, challenge derivation, proof
parsing, or EOF checks into the public wrapper implementations.

### 10.5 DSFS concepts removed

Remove:

- `DsfsArgument<IA, ...>` as a conditionally capable wrapper,
- `DsfsReduction<IR, ...>` as a conditionally capable wrapper,
- `PreprocessedDsfsArgument<IA, ...>` as a dual-role wrapper,
- `PreprocessedDsfsReduction<IR, ...>` as a dual-role wrapper,
- `CombinedNarg`,
- constructors returning a wrapper that might implement both roles, and
- DSFS forwarding of the indexer/preprocessing trait.

The only compiled outputs are native prover or verifier roles.

### 10.6 Proof-format agreement

Independently compiled roles must agree on:

- `protocol_id`,
- instance encoding,
- sponge selection,
- salt length and salt policy,
- session encoding,
- committed-index encoding for preprocessing protocols,
- message serialization, and
- transcript/NARG layout version.

The first implementation phase should preserve the current derivation exactly.
An optional diagnostic format descriptor may expose these values for deployment
checks, but it must not be newly absorbed into the transcript as part of this
refactor.

---

## 11. Composition Changes

Composition becomes role-specific by construction.

### 11.1 Plain composition

`ChainedReduction<First, Second>` can remain a generic container. It implements a
role only when its components implement that role:

```rust
impl<First, Second> InteractiveReductionProver
    for ChainedReduction<First, Second>
where
    First: InteractiveReductionProver,
    Second: InteractiveReductionProver<
        SourceInstance = First::TargetInstance,
        SourceWitness = First::TargetWitness,
    >,
{
    // ...
}
```

The verifier impl has no witness equality bound:

```rust
impl<First, Second> InteractiveReductionVerifier
    for ChainedReduction<First, Second>
where
    First: InteractiveReductionVerifier,
    Second: InteractiveReductionVerifier<
        SourceInstance = First::TargetInstance,
    >,
{
    // ...
}
```

`ReducedArgument<R, A>` follows the same pattern:

- prover composition relates target instance and target witness types,
- verifier composition relates only target instance types.

A prover composition value and verifier composition value may have different
component concrete types.

### 11.2 Preprocessing composition

Indexers compose separately from executable roles:

```text
ChainedIndexer<I1, I2>
ReducedArgumentIndexer<IRIndexer, IAIndexer>
```

They pair:

```text
Index       = (I1::Index, I2::Index)
ProverKey   = (I1::ProverKey, I2::ProverKey)
VerifierKey = (I1::VerifierKey, I2::VerifierKey)
```

Prover composition routes only prover-key tuples. Verifier composition routes
only verifier-key tuples.

### 11.3 Plain-to-preprocessing adapters

The current adapters combine trivial indexing with executable roles. Split them
into:

```text
TrivialIndexer
TrivialIndexedArgumentProver<P>
TrivialIndexedArgumentVerifier<V>
TrivialIndexedReductionProver<P>
TrivialIndexedReductionVerifier<V>
```

All trivial keys remain `()` with an empty committed index. The preprocessing
transcript still differs from the plain transcript because it absorbs the indexed
instance wrapper.

### 11.4 NARG-to-interactive adapters

Replace the full `NargAsInteractiveArgument<N>` adapter with role-specific
adapters:

```text
NargProverAsInteractiveArgument<P>
NargVerifierAsInteractiveArgument<V>
```

Each adapter fixes a session and exposes only its corresponding interactive role.
There is no adapter that requires or reconstructs a full NARG object.

---

## 12. Security Metadata Changes

Security metadata currently extends full executable conjunction traits. Those
supertrait bounds must be removed.

Plain metadata is implemented on verifier roles. This keeps security claims next
to the acceptance algorithm while still avoiding any witness or prover-key
capability:

```rust
pub trait ArgumentSecurity: ArgumentCore {
    // Existing security associated types and methods.
}

pub trait ReductionSecurity: ReductionCore {
    // Existing security associated types and methods.
}
```

Preprocessing metadata is implemented on indexer roles. The indexer owns the
public protocol shape, both key commitments, and the static index parameters, but
has no proving or verification method:

```rust
pub trait PreprocessingArgumentSecurity: ArgumentCore + Indexer {
    // Existing index and instance security metadata.
}

pub trait PreprocessingReductionSecurity: ReductionCore + Indexer {
    // Existing index, source, and target security metadata.
}
```

This ownership is deliberate: plain security follows the verifier, while
preprocessing security follows the indexer. Neither security surface grants
prover capabilities.

Composition keeps its existing security calculations, but its bounds refer to
security metadata traits and public cores rather than full executable
conjunctions.

---

## 13. Live-Channel Changes

The channel traits and `live-channel` transport do not change.

Live execution receives two different body types:

```rust
fn run_live_argument<P, V>(
    prover: P,
    verifier: V,
    instance: P::Instance,
    witness: P::Witness,
) where
    P: InteractiveArgumentProver,
    V: InteractiveArgumentVerifier<Instance = P::Instance>,
{
    // Spawn each role with one side of channel_pair().
}
```

Preprocessing live execution additionally accepts `P::ProverKey` and
`V::VerifierKey`. The indexer runs before the two role threads are started and is
not part of the channel protocol.

---

## 14. Migration Plan

### Phase 0: Lock transcript behavior

Before changing traits:

1. Preserve current sigma-proofs `StdHash` golden vectors.
2. Add byte-equality tests for native one-sided plain argument compilation.
3. Add byte-equality tests for preprocessing arguments and reductions.
4. Retain verifier EOF/trailing-data tests.

### Phase 1: Change `ia-core` cores and leaves

1. Move witnesses from `ArgumentCore` to `ArgumentProverCore`.
2. Move reduction witnesses from `ReductionCore` to `ReductionProverCore`.
3. Introduce `Indexer`.
4. Move prover and verifier key associated types onto their executable role
   traits.
5. Remove all full conjunction traits.
6. Update the prelude to export only cores and native role traits.

### Phase 2: Replace authoring macros

1. Add shared pair/triple declarations that dispatch one source body into
   independent role impls.
2. Add role-specific suffix macros for separately bounded or separately housed
   roles.
3. Test generics, attributes, where clauses, shared field routing, and every
   suffix form.
4. Add compile-fail documentation tests showing that verifier roles have no
   witness or prover-key capability.

### Phase 3: Split DSFS public wrappers

1. Add explicit argument prover/verifier wrappers.
2. Add explicit reduction prover/verifier wrappers.
3. Add preprocessing counterparts.
4. Reuse the existing private transcript runners.
5. Remove preprocessing/indexer forwarding.
6. Remove `CombinedNarg`.

### Phase 4: Migrate plain protocols

Start with Schnorr:

1. Define native `SchnorrProver` and `SchnorrVerifier`.
2. Compile each independently through DSFS.
3. Assert proof bytes equal the pre-refactor implementation.
4. Run both roles through `live-channel`.

Then migrate sumcheck, composition examples, Bulletproof examples, and
`sigma-bridge`.

`sigma-bridge` is compatibility-oriented. If the upstream `sigma-proofs` trait
remains monolithic, Argus may expose separate `SigmaProver` and `SigmaVerifier`
adapter types, but that does not create a dependency boundary inside the upstream
crate. The bridge must document this limitation rather than presenting the
adapter as a native approach-3 implementation.

### Phase 5: Migrate preprocessing protocols

Start with a small preprocessing example:

1. Extract its indexer into a third type.
2. Ensure the prover crate/type only knows `ProverKey`.
3. Ensure the verifier crate/type only knows `VerifierKey`.
4. Check committed-index equality at indexing time.
5. Assert DSFS proof bytes are unchanged.

Then migrate WARP and the remaining preprocessing examples.

### Phase 6: Migrate composition, adapters, and security

1. Relax verifier composition bounds so they do not mention witnesses.
2. Add independent indexer composition.
3. Split trivial-index and NARG-to-interactive adapters by role.
4. Remove full executable bounds from security metadata.
5. Update docs and examples to show native roles only.

### Phase 7: Remove transitional APIs

Delete:

- role views,
- full conjunction traits,
- body and NARG recombination,
- old macro forms,
- old DSFS constructors, and
- stale documentation describing approaches 1, 2, 4, or 5 as supported
  production paths.

Research adapters may be reconsidered after the role-first production path is
complete and stable.

---

## 15. Transcript Invariant Review

This architecture change is not permission to modify transcript semantics.

Every implementation and review must confirm:

1. All prover messages are absorbed before the corresponding challenge.
2. Protocol ID, session, committed index where applicable, and instance are
   absorbed before the first challenge.
3. Replay remains deterministic.
4. Challenges are not reused across rounds.
5. Protocol implementations mutate only their explicit local state and channel.
6. All transcript operations remain explicit in the backend.
7. DSFS Construction 4.3 ordering remains unchanged.
8. Transcript logic is not duplicated between role wrappers.
9. `ia-core` traits remain independent of sponge/transcript internals.
10. Sponge operations remain exclusively in `spongefish::dsfs`.
11. Verification consumes the full expected proof and rejects trailing bytes.

The expected result is byte-identical proofs before and after the refactor for
the same protocol, sponge, salt policy, session, instance, witness, keys, and
randomness.

---

## 16. Test Plan and Definition of Done

Minimum targeted commands during development:

```text
cargo test -p ia-core
cargo test -p spongefish-dsfs
cargo test -p sigma-bridge
cargo test -p warp
```

Final commands:

```text
cargo check
cargo test
```

Required behavioral tests:

- native prover and verifier roles compile independently,
- verifier types expose no witness associated type,
- preprocessing prover types expose no verifier key,
- preprocessing verifier types expose no prover key,
- indexer types expose no prove or verify method,
- mismatched committed indexes fail the indexer consistency check,
- mismatched protocol IDs are detected by integration tests,
- plain argument proofs remain byte-identical,
- preprocessing argument proofs remain byte-identical,
- plain reduction proofs remain byte-identical,
- preprocessing reduction proofs remain byte-identical,
- sigma-proofs `Shake128` golden vectors remain byte-for-byte identical,
- Keccak paths remain green,
- verifier EOF checks continue rejecting trailing proof data, and
- live prover/verifier execution works with different concrete role types.

The change is complete only when the full Argus and spongefish workspaces pass
without restoring a full-body production path.

---

## 17. Final Architecture Summary

The new unit of abstraction is a deployable role:

```text
Indexer  = setup algorithm + setup configuration
Prover   = prover algorithm + prover configuration
Verifier = verifier algorithm + verifier configuration
```

The roles share a proof format, not a concrete implementation type.

Macros implement one native role per invocation. DSFS compiles one native role
per constructor. Composition combines like roles. Security metadata describes
the public protocol rather than requiring a full executable object.

This gives Argus a production architecture that naturally supports separate
machines, separate crates, recursion, and role-specific configuration while
leaving all transcript mechanics in the DSFS backend.
