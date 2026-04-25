# Contributing

Argus is a research-oriented Rust workspace for public-coin interactive
arguments, reductions, and DSFS compilation.

## Workflow

1. Open or find an issue/design thread for nontrivial changes.
2. Discuss API, transcript, or security-model changes before implementing them.
3. Work on a topic branch.
4. Keep the diff scoped to the protocol/backend/API surface being changed.
5. Run the relevant golden commands before opening a PR.

Small typo fixes and narrow documentation improvements do not need a design
thread.

## Golden Commands

```bash
cargo build
cargo test
cargo test -p warp
```

For documentation-only changes, check links and build rustdoc when relevant:

```bash
cargo doc --workspace --no-deps
```

## Documentation Policy

Argus uses three documentation layers:

- `README.md`: short project overview, crate map, and quickstart.
- Rustdoc: API-level documentation owned by the crate that defines the API.
- `docs/`: architecture, security notes, protocol guides, ADRs, and historical
  design notes.

When changing complex protocol code, leave the code more documented than it
started. Prefer a short high-level explanation, a reference to the relevant
paper section, or a compact proof sketch before non-obvious logic.

When changing a durable design rule, add or update an ADR in `docs/adr/`.

When superseding a versioned design note, preserve it under `docs/history/`
instead of rewriting it into the current docs. The current docs should explain
what to do now; history should explain how the design evolved.

## Transcript and Security Changes

Changes to transcript ordering, domain separation, sponge choice, salt policy,
proof layout, or DSFS security bookkeeping require explicit review against:

- `docs/security/transcript-invariants.md`
- `docs/security/domain-separation.md`
- `docs/security/dsfs-bounds.md`

Protocol code must continue to use only the `ia-core` channel API.
