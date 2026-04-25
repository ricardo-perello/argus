# DSFS Ownership Options


Current shape:

```text
dsfs -> ia-core -> spongefish
```

`ia-core` owns the abstract Argus interfaces (`InteractiveArgument`,
`InteractiveReduction`, channels, security profiles), but it currently depends on
`spongefish` for codec traits.

The target from our discussion was:

- Argus owns abstract proof-system types: IA, IR, future `Narg`.
- The spongefish side owns the DSFS transformation `IA/IR -> NARG`.

Here "spongefish side" needs one packaging decision. The spongefish repo is
already a workspace, and Argus currently depends on the core package named
`spongefish` at `../spongefish/spongefish`. If DSFS moves directly into that
core `spongefish` crate while `ia-core` still depends on `spongefish`, we get a
dependency cycle:

```text
ia-core -> spongefish -> ia-core
```

I see two realistic options.

## Option 1: New `spongefish-dsfs` sibling crate in the spongefish workspace

```text
ia-core -> spongefish

spongefish-dsfs -> ia-core
spongefish-dsfs -> spongefish
```

DSFS moves out of Argus into a new crate in the spongefish workspace, next to
the core `spongefish` crate. The core `spongefish` crate itself stays independent
of Argus.

Pros:

- No dependency cycle.
- Minimal refactor.
- No codec-trait redesign.
- DSFS is owned by the spongefish workspace/family.

Cons:

- DSFS is not inside the core `spongefish` crate itself.
- `ia-core` still depends on spongefish codec traits.

This is my current recommendation.

## Option 2: Move codec traits into `ia-core`, then put DSFS inside the core `spongefish` crate

```text
spongefish -> ia-core
```

Argus owns IA/IR/NARG and also the codec traits needed by channels. Then the
core `spongefish` crate can depend on `ia-core` and host DSFS directly.

Pros:

- Cleanest conceptual split.
- `ia-core` becomes the true abstract layer.
- DSFS can live inside the core `spongefish` crate.

Cons:

- Much larger refactor.
- Requires moving or replacing spongefish codec traits and impls.
- Higher risk of breaking existing spongefish/Argus code.

My recommendation is Option 1 unless you specifically want DSFS inside the core
`spongefish` crate rather than just owned by the spongefish workspace/family.
