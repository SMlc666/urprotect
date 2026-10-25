# Bounded Zero-File PT_TLS Observation Design

## Intent

The nightly `zig-musl` fixture executes successfully on the AArch64 runner and passes the independent ELF oracle, but UrProtect rejects its zero-file `PT_TLS` marker because the marker has a nonzero virtual address and no owning `PT_LOAD`. Preserve this valid structural observation without treating it as a usable TLS module.

## Goals

- Accept a structurally bounded, ownerless `PT_TLS` only when `p_filesz == 0` and `p_offset` is inside the source image (including the valid empty range at EOF).
- Continue checking nonzero `p_memsz`, `p_filesz <= p_memsz`, checked virtual-memory end arithmetic, alignment, permissions, and every non-empty file range.
- Record no owner (`OwningLoadProgramHeaderIndex == -1`) and do not allocate or copy template bytes.
- Keep `TlsStructuralAdapter.CreateImageModule` fail-closed when the PT_TLS segment has no unique owning `PT_LOAD`.
- Continue rejecting ownerless nonzero-file TLS and ownerless zero-file TLS with an out-of-bounds file offset.

## Non-goals

- Do not relax TLS relocation, symbol, GOT, descriptor, or load-owner validation.
- Do not claim managed or native TLS support for this shape.
- Do not change the Zig toolchain or remove the required fixture.

## Approaches

1. **Broaden the bounded structural-observation predicate (selected).** Permit any virtual address for an ownerless zero-file PT_TLS after existing arithmetic, permission, alignment, and file-offset bounds checks. Keep owner index `-1`; the semantic adapter continues rejecting it. This is the smallest change and matches the separation between structural facts and usable semantic ownership.
2. **Change the Zig linker recipe.** Avoids changing parser behavior but makes the fixture depend on a toolchain-specific workaround and obscures whether the current ELF shape is usable.
3. **Remove or de-require the Zig fixture.** Hides the incompatibility and reduces compiler/runtime coverage without fixing the parser contract.

## Constraints and acceptance

The code change is limited to the `PT_TLS` structural parser and its structural regression tests. Tests must prove that a bounded ownerless zero-file PT_TLS with nonzero `p_vaddr` parses to a fact with no owner, while semantic projection still fails with `TlsBindingUnresolved`; an ownerless nonzero-file template and an out-of-bounds empty-file offset remain rejected. Existing mapped-template tests remain unchanged. The AArch64 nightly fixture job must subsequently execute and validate the Zig output and its no-op copy; that hosted observation is fixture evidence only, not a TLS-support claim.
