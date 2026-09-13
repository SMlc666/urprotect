# Expand AArch64 PIE compatibility

## Goal

Expand the accepted and provable AArch64 ELF64 little-endian ET_DYN
compatibility language under the shared in-process HostContext runtime.

## Requirements

- Start from the current parser/validator boundary: AArch64, ET_DYN,
  bounded program headers/load map, PT_DYNAMIC, and an executable entry
  mapping.
- Classify feature obligations for segment alignment/layout, section-table
  absence, PT_INTERP, PT_TLS, GNU stack/RELRO/property notes, dynamic
  tags, RELA/RELR/Android packed relocations, symbol versions, TLS, and
  dependency resolution.
- Expand relocation and runtime handling only when the Host Contract has a
  defined semantic for the feature.
- Add compiler/toolchain fixtures that exercise distinct ELF shapes and
  lifecycle behavior, not merely duplicate language labels.
- Maintain paired positive and negative cases. Unknown or unproven behavior
  remains unknown or rejected, never silently supported.
- Keep the existing analysis/reporting and malformed-input diagnostics stable
  unless a deliberate migration is recorded.

## Dependencies and Ordering

- Depends on the Host Contract and entry ABI from
  09-13-unified-runtime-host-contract.
- Feeds feature identifiers, fixtures, proof obligations, and evidence paths
  into 09-13-compatibility-matrix-evidence.
- The compatibility matrix must not mark a feature proven before this child
  supplies the required runtime and model evidence.

## Acceptance Criteria

- [ ] A feature inventory maps current parser fields and validator rules to
      explicit compatibility obligations.
- [ ] At least one expanded segment/layout case, one relocation case, and one
      lifecycle/dependency case have positive and negative coverage.
- [ ] Existing GCC/Clang/Rust/Go/Zig/NativeAOT fixtures are classified by
      exercised ELF/runtime features.
- [ ] Stripped/sectionless and malformed cases are covered where they are
      relevant to program-header-based loading.
- [ ] Every accepted feature has a deterministic test oracle and a documented
      reason it is within the Host Contract.
- [ ] Unsupported features produce stable rejection/unknown diagnostics and
      cannot enter the runtime as if proven.

## Out of Scope

- Non-AArch64 architectures, PE, Mach-O, and .NET assembly protection.
- Arbitrary standalone process entry emulation.
- Broad claims based only on one emulator, one OEM, or one compiler version.

## Notes

- Keep `prd.md` focused on requirements, constraints, and acceptance criteria.
- The child design and implementation artifacts are present; implementation
  still waits for the parent planning review and task start.
