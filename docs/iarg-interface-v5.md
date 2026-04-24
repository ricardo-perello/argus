# IA v5: Collapsed traits, `ProtocolSecurity`, and split protocol id

## Motivation

v4 added security metadata directly on `InteractiveArgument` and `InteractiveReduction`. This caused two problems:

1. **Proliferation of trait objects.** The original design required separate `Prove<P>` / `Verify<V>` traits generic over the channel type, plus `ReduceProve<P>` / `ReduceVerify<V>` counterparts. Composition structs (`ChainedReduction`, `ReducedArgument`) needed three impl blocks each. Protocol authors had to write one impl per bound combination.

2. **Protocol id overflowed 64 bytes.** The DSFS domain separator was derived by formatting a human-readable string including the generic type name (`type_name::<IA>()`), which overflows 64 bytes for any non-trivial generic. This broke the Schnorr example and any other protocol with a type-parameter-qualified name.

## Changes in v5

### 1. Collapsed `prove`/`verify` into `InteractiveArgument`

Before:

```rust
trait InteractiveArgument { fn protocol_id() -> [u8; 64]; fn security() -> SecurityProfile; }
trait Prove<P: ProverChannel> { fn prove(ch, instance, witness); }
trait Verify<V: VerifierChannel> { fn verify(ch, instance) -> VerificationResult<()>; }
```

After:

```rust
pub trait InteractiveArgument {
    type Instance;
    type Witness;
    fn protocol_id() -> [u8; 32];
    fn prove<P: ProverChannel>(ch: &mut P, instance: &Self::Instance, witness: &Self::Witness);
    fn verify<V: VerifierChannel>(ch: &mut V, instance: &Self::Instance) -> VerificationResult<()>;
}
```

Same change for `InteractiveReduction` — `ReduceProve<P>` / `ReduceVerify<V>` collapsed into generic methods on the trait.

### 2. Extracted `ProtocolSecurity` as a separate trait

Security metadata is now a separate opt-in trait:

```rust
pub trait ProtocolSecurity {
    fn security() -> SecurityProfile;
}
```

`ChainedReduction` and `ReducedArgument` provide conditional `ProtocolSecurity` impls when both sub-protocols implement it. Protocols without fully specified bounds can implement the core traits without providing security metadata.

### 3. Split protocol id: `[u8; 32]` IA label + `[u8; 32]` sponge tag

**Old:** `protocol_id() -> [u8; 64]`, with DSFS deriving the domain separator by hashing `(ia_id || type_name::<H>() || salt)` — which works but is opaque and non-interoperable.

**New:** `protocol_id() -> [u8; 32]`, and DSFS builds the 64-byte domain separator as:

```
DomainSeparator::new( ia_id[32] || sponge_tag[32] )
```

where `sponge_tag` is a 32-byte zero-padded ASCII constant on the sponge type via the `SpongeTag` trait:

```rust
pub trait SpongeTag: ByteDuplexSponge {
    const TAG: [u8; 32];
}
// Keccak::TAG  = b"keccak\0..."
// StdHash::TAG = b"shake128\0..."
```

This mirrors sigma-proofs' convention: for `CanonicalLinearRelation<BLS12381>` with StdHash, the domain separator is:

```
bytes  0-31: "sigma-proofs_Shake128_BLS12381\0\0"  ← ia protocol_id()
bytes 32-63: "shake128\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"  ← SpongeTag
```

Human-readable, no hashing, and structurally compatible with sigma-proofs' ciphersuite label convention.

Protocol authors use the `ia_core::pad_protocol_id` helper:

```rust
fn protocol_id() -> [u8; 32] {
    ia_core::pad_protocol_id(b"schnorr")
}
```

`pad_protocol_id` is a `const fn` that zero-pads a byte slice and panics at compile time if the label exceeds 32 bytes.

## Impact on composition

`derive_composition_id` in `compose.rs` now operates on `[u8; 32]` arrays. The XOR-based derivation is otherwise unchanged — it produces a unique 32-byte ID for each composition, and DSFS appends the sponge tag at compile time.

## Impact on sigma-bridge

`SigmaIA<S>` now has `protocol_id() -> [u8; 32]`. For `SigmaIA` proofs through `spongefish::dsfs::prove`, the domain separator is `protocol_identifier()[:32] || sponge_tag`, which differs from sigma-proofs `Nizk` (which uses the full raw 64-byte `protocol_identifier()` with no sponge tag appended). These are two distinct proof formats:

| Path | Domain sep | Compatible with `Nizk`? |
|---|---|---|
| `sigma_bridge::prove` | `protocol_identifier()` raw [64 bytes] | Yes |
| `SigmaIA` + `spongefish::dsfs::prove` | `protocol_id()[32] \|\| sponge_tag[32]` | No |

Spec-compatible proofs must still use `sigma_bridge::prove`/`verify` directly.

## File references

- IA interface: [../crates/ia-core/src/argument.rs](../crates/ia-core/src/argument.rs)
- IOR interface: [../crates/ia-core/src/reduction.rs](../crates/ia-core/src/reduction.rs)
- Composition: [../crates/ia-core/src/compose.rs](../crates/ia-core/src/compose.rs)
- `pad_protocol_id`: [../crates/ia-core/src/lib.rs](../crates/ia-core/src/lib.rs)
- `SpongeTag` + DSFS domain sep: `spongefish/spongefish/src/dsfs/params.rs`, `spongefish/spongefish/src/dsfs/compile.rs`
- `SigmaIA`: [../crates/sigma-bridge/src/ia.rs](../crates/sigma-bridge/src/ia.rs)
- Prior version: [iarg-interface-v4.md](iarg-interface-v4.md)
