# Repository research: semantic boundaries to promote

The requested support expansion covers five coupled domains:

1. **Layout and address mapping**: no PT_NULL prerequisite, program-header table expansion/relocation, segment permissions/alignment, veneers, and branch relaxation.
2. **AArch64 semantic relocation**: PC-relative branches/calls, ADR/ADRP, literal pools, internal/external targets, and ELF relocation records.
3. **Indirect control flow**: exact/bounded/runtime target resolution, jump-table representation, relocation, and behavior checks.
4. **TLS**: PT_TLS, local/initial-exec/dynamic/TLSDESC models, GOT/dynamic relocation, per-thread state, lifecycle, and runtime-specific loader behavior.
5. **CFI/unwind**: bounded CIE/FDE and `.eh_frame_hdr` parsing, range remapping, generation, repair/canonicalization, exceptions, backtrace, and cancellation/signal unwind.

These domains require one immutable semantic rewrite plan plus one physical ELF layout plan. A raw-byte copy path cannot own all of these semantics. Unrecoverable or genuinely undefined metadata remains a deterministic pre-publication diagnostic; supported inputs must have a positive fixture and a runtime oracle.
