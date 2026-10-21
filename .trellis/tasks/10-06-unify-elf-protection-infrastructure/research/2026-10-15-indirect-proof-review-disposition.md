# Indirect-call proof review disposition

## Authoritative inputs

- Implementer: `39f1aac6-e3b6-431e-9e2e-15a1a7ae6976`.
- Independent reviewer: `23619956-65b2-427a-a60b-18d6f2c0decb`.
- Reports: runtime-managed handoff/review outputs under workflow `e8d2057f-0072-46e7-a896-0318b1984e4d`.
- Checkout: `/root/urprotect`, `feat/indirect-control-jump-tables`, HEAD `f7b2128`; dirty shared worktree retained. No commit, staging, or runtime-row promotion.

## Evidence and verdict

The real registered-worker fixture has a successful selected-function producer and rehydrator path, independently inspected with project decoding and readelf. The implementer reports 418 passing managed tests. Neither report claims worker runtime execution. Independent review is **BLOCK**, despite the bounded positive materialization result.

## Accepted findings and sequential owners

All five findings are accepted as unresolved correctness/contract issues, not dismissed by positive managed tests:

1. **P1 memory effects and stale guards.** A real-fixture in-memory mutation at VAs 0xb88/0xb8c (`ADD X9,X6,#64`; `STLR XZR,[X9]`) clears the join callback after its guard. The analyzer and in-memory final workflow nevertheless succeed. Store classification and call-side memory effects must conservatively invalidate dependent guards and facts. Exact or documented no-alias/effect summaries require proof, not a name/register whitelist.
2. **P2 jump-table reaching definitions.** An architectural W/X index alias can be overwritten after CMP/B.HI and before the indexed load. Bound ownership requires unchanged reaching definitions or rejection of overlapping writes.
3. **P2 snapshot owner relation.** Typed dynamic import owner facts currently become a runtime-binding string plus an independent relocation extension. Carry and cross-validate the call/GOT/relocation/dynsym/address-map relation through canonical decoding and rehydration.
4. **P2 HostContext root identity.** Seeding every selected function's X0 as HostContext is not an ABI proof. Bind the root to a verified invocation/profile contract or retain an accurately typed caller-owned callback classification until it is established.
5. **P2 producer bound.** Silently retaining only 64 producer addresses contradicts fail-closed provenance. Track overflow and reject a proof that exceeds its declared bound, with focused regression coverage.

Immediate single-writer stage: fix (1) and (5) in the dataflow/memory-effect seam, add failing-before/passing-after nearest-negative tests using actual project-decoded operand shapes, then independently recheck that seam. Other managed seams (2)-(4) remain mandatory follow-up work; they are not waived or a reason to claim core completion. If sound call-effect invalidation exposes a legitimate positive-path gap, report the exact missing contract rather than retain stale guards.

After the managed proof contracts pass independent review, integrate real source/transformed registered-worker execution, lifecycle order, serial/concurrent dispatch and row-bound artifacts. Parent R4/R5/R6 and other-runtime/profile evidence remain open. Spec updates, final full-scope checks, commit and finish-work remain subsequent required phases.
