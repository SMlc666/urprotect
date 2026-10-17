# Technical design: bounded CFI and unwind metadata rewriting

## Boundary

This child owns structural .eh_frame/.eh_frame_hdr parsing, bounded CIE/FDE
models, address-map remapping, canonical repair of recoverable records, and
layout edits for selected transformed ranges. It consumes the existing
SemanticRewritePlan, AddressMap, ElfLayoutPlan, and SemanticCfiEffectExtension;
it does not add a second artifact format, direct ELF writer, loader, or
runtime-specific ABI.

StructuralElf remains the owner of ELF headers, sections, load maps, and
bounded byte ranges. UnwindMetadata owns DWARF CFI record semantics.
ElfLayoutPlanner owns placement and edit ordering. ElfLayoutMaterializer owns
atomic application, reparsing, and no-publication behavior. Runtime
scripts/native fixtures own unwind execution evidence.

## Data flow

    ElfFile.SectionHeaders + bounded section bytes
      -> UnwindMetadataParser
      -> UnwindMetadataModel (CIE/FDE/header/index + diagnostics)
      -> UnwindRewritePlanner(source model, AddressMap, CFI effects)
      -> typed ElfLayoutByteEdit requests
      -> ElfLayoutMaterializer
      -> output parse + unwind model reparse
      -> evidence/behavior oracle

The parser is observation-only until a selected transformation requests a
rewrite. Generic validation and packing do not disassemble or rewrite unwind
data. A missing section or sectionless image is an explicit not-applicable
boundary unless a program-header-owned unwind contract is supplied.

## Model

Add project-owned records under src/UrProtect.Core/UnwindMetadata/:

- UnwindSectionKind: EhFrame and EhFrameHeader.
- UnwindEncoding: DW_EH_PE format/application/indirect flags with bounded
  decode/encode helpers.
- UnwindCie: record range, version, augmentation, code/data alignment,
  return-address register, initial instructions, augmentation payload, and
  canonical bytes.
- UnwindFde: record range, CIE reference, initial location, address range,
  augmentation payload, CFA instructions, source/output ranges, and canonical
  bytes.
- UnwindInstruction: opcode, operands, byte range, and recognized semantic
  effect: AdvanceLoc, DefCfa, DefCfaRegister, DefCfaOffset, Offset, Restore,
  RememberState, RestoreState, Nop, or Unsupported.
- EhFrameHeader: version, pointer encodings, FDE count, sorted table entries,
  and raw/decoded bounds.
- UnwindMetadataModel: source section ranges, CIE/FDE collections, optional
  header, unknown augmentation/encoding state, and canonical digest.
- UnwindRewriteResult: rewritten section bytes, edits, model, diagnostics, and
  evidence fields.

All counts, record lengths, ULEB/SLEB values, alignment, pointer arithmetic,
and section-relative offsets are bounded by shared limits. Unknown opcodes or
augmentation semantics are preserved as opaque bytes when the record can be
bounded; a record needed for a transformed range fails with a stable
unsupported diagnostic rather than guessed semantics.

## Parsing contract

The parser supports ELF64 little-endian .eh_frame records:

1. Read 32-bit length or extended 64-bit length.
2. Require record end inside the section and enforce a maximum record size.
3. Interpret CIE id 0 and FDE backward CIE pointer according to .eh_frame
   relative offsets.
4. Decode CIE version, augmentation string, code/data alignment, return-address
   register, z augmentation length/payload, and initial CFI bytes.
5. Decode FDE CIE reference, encoded initial location/range, z augmentation,
   and instruction stream.
6. Decode .eh_frame_hdr version 1 and three pointer encodings, FDE count, and
   table entries; require sorted, in-range entries and exact table bounds.
7. Retain unknown augmentation bytes and unsupported pointer/opcode facts in
   the model; never treat malformed lengths as empty records.

The first promoted instruction semantics are the DWARF CFA operations emitted by
the pinned GCC/Clang AArch64 fixtures: advance_loc variants, nop, def_cfa,
def_cfa_register, def_cfa_offset, offset, restore, remember_state, and
restore_state. Other instructions remain opaque and force an explicit
unsupported rewrite result when their affected FDE must move.

## Rewrite contract

For each FDE whose source range maps through AddressMap:

- map initial location and range through the old/new virtual address map;
- preserve the CIE reference and augmentation bytes;
- remap advance_loc PC deltas when transformed instruction ranges retain a
  monotonic mapping; otherwise split/rebuild only with a typed plan request;
- inject canonical CFI effects from SemanticCfiEffectExtension at the mapped
  instruction boundary;
- regenerate FDE length and .eh_frame_hdr initial-location/FDE-address entries
  with the same pointer encoding;
- retain unrelated CIE/FDE records byte-for-byte;
- reject overlapping, non-monotonic, missing, or ambiguous mappings before
  layout publication.

The first implementation does not synthesize arbitrary DWARF expressions or
guess frame rules. It supports identity/piecewise-linear mapped ranges and
canonicalizes only recoverable malformed lengths/ordering. An unrecoverable
record returns UnwindMetadataMalformed or UnwindMetadataUnsupported and no
output edit.

## Layout integration

UnwindRewritePlanner returns ElfLayoutByteEdit values with
ElfLayoutEditKind.UnwindMetadata. The planner rejects overlap with generated
code, program-header, TLS, or other metadata edits. The materializer applies
sorted edits, reparses the complete output, reparses unwind sections, and
requires source/output CIE identity, mapped FDE identity, header table
consistency, and digest agreement before returning bytes.

Section headers may be absent. In that case, a transformed request requiring
CFI returns a deterministic UnwindMetadataUnavailable result and publishes
nothing. This is distinct from a structurally valid image with no applicable
FDE, which is not-applicable evidence.

## Evidence and lifecycle

Each CFI row retains source/output .eh_frame and .eh_frame_hdr ranges,
source/output hashes, CIE/FDE counts, mapped range count, canonicalization
status, first-failure stage, and publication/rollback status. Native fixtures
compare baseline and transformed status, stdout/stderr, backtrace/function
identity, exception/cancellation behavior where supported, and artifact
hashes. Glibc, musl, and bionic evidence is separate; unavailable tooling is
row-local environment-unavailable.

## Failure and rollback

Malformed section bounds, record lengths, CIE references, pointer encodings,
augmentation payloads, ULEB/SLEB overflow, header table order, mapping gaps,
edit overlap, output reparse mismatch, digest mismatch, or unsupported
instruction semantics return stable diagnostics and no output bytes. Temporary
edits are held in memory until materializer validation; publisher state is
unchanged on every failure. Dedicated native transformed CFI behavior evidence
is a separate runtime-owned slice; the current managed contract explicitly
records that no glibc, musl, or bionic CFI execution claim is promoted without
its own retained native fixture and baseline comparison.

## Compatibility

No Payload Frame v3, HostContext ABI v1, Protected Image ABI v1, or semantic
snapshot grammar change is introduced. Existing SemanticCfiEffectExtension
remains the snapshot carrier. New UnwindMetadata types are Core-only and
project-owned; no AsmStone or third-party DWARF type escapes the boundary.
