# Documentation History

This directory preserves design history that should remain readable without
requiring Git archaeology.

Stable documentation lives in `architecture/`, `author-guide/`, `security/`,
`api/`, and `protocols/`. Historical files can be corrected for broken links,
but their original design intent should not be rewritten into current-state
documentation.

ADRs in `docs/adr/` record accepted decisions. The files here are broader:
iterations, abandoned approaches, review memos, and implementation snapshots.

## Map

- `docs/history/interface/`: IA/IR trait and composition iterations.
- `docs/history/security/`: security profile refactors and theorem bookkeeping.
- `docs/history/domain-separation/`: domain-separation redesign notes.
- `docs/history/backends/`: DSFS ownership and backend integration notes.
- `docs/history/protocols/`: protocol-specific historical notes.
- `docs/history/plans/`: internal design notes and review presentations that
  are useful archive material but not part of the stable public guide.

## Rendered Archive Pages

- [WARP implementation notes](protocols/warp-implementation-notes.md)
- [Superseded prover/verifier split presentation](plans/prover-verifier-split-presentation.md)

## Other Archived Files

These files are kept in the repository but are not rendered as mdBook chapters:

- `docs/history/interface/iarg-interface-v1.md`
- `docs/history/interface/iarg-interface-v2.md`
- `docs/history/interface/iarg-interface-v3.md`
- `docs/history/interface/iarg-interface-v4.md`
- `docs/history/interface/iarg-interface-v5.md`
- `docs/history/interface/iarg-interface-v6.md`
- `docs/history/interface/interactive-reduction-v1.md`
- `docs/history/interface/interactive-reduction-v2.md`
- `docs/history/backends/dsfs-ownership-options.md`
- `docs/history/backends/dsfs-v2.md`
- `docs/history/domain-separation/domain-sep-refactor-summary.md`
- `docs/history/domain-separation/domain-separation-redesign-2026-04-plan.md`
- `docs/history/protocols/examples-vs-warp.md`
- `docs/history/protocols/sigma-bridge-v1.md`
- `docs/history/protocols/sigma-bridge-v2.md`
- `docs/history/protocols/sigma-bridge-v3.md`
- `docs/history/security/security-profile-rbr-refactor.md`
- `docs/history/plans/protocol-core-dsfs-presentation.md`
- `docs/history/plans/keys-as-inputs-preprocessing-presentation.md`
- `docs/history/plans/preprocessing-indexed-relations.md`
- `docs/history/plans/preprocessing-indexed-relations-v2.md`
- `docs/history/plans/argument-prover-verifier-trait-split.md`
- `docs/history/plans/report-notes.md`
