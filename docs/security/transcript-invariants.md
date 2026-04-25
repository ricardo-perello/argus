# Transcript Invariants

These invariants are non-negotiable for backend and transcript changes.

1. All prover messages are absorbed before any challenge is squeezed.
2. Public inputs are absorbed before the first challenge.
3. Transcript replay is deterministic.
4. No challenge is reused across rounds.
5. No implicit state mutation occurs outside the transcript or channel.
6. All transcript operations are explicit.
7. Absorb/squeeze ordering follows DSFS Construction 4.3.
8. Cryptographic logic is not duplicated across modules.
9. The IA abstraction does not depend on transcript internals.
10. DSFS is the only layer where sponge operations occur.

## Review Checklist

When changing protocol execution or transcript wiring, check:

- Does the per-round shape still absorb every prover message before squeezing
  the challenge?
- Are protocol id, sponge info, session id, and instance bytes fixed before the
  first challenge?
- Does verifier replay use the same messages in the same order?
- Does verification reject or error on malformed proof bytes?
- Does a change to transcript layout, sponge choice, or salt policy require a
  new DSFS-level `protocol_id`?

Protocol implementations should not need to know these details. If they do, the
backend boundary is probably leaking.
