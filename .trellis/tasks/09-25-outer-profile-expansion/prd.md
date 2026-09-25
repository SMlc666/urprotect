# Expand outer-execveat compatibility

## Goal

Broaden AArch64 executable coverage for the `outer-execveat` profile while
proving that packaging preserves baseline process behavior on every runtime
family included in the support claim.

## Dependencies and constraints

- Depends on the architecture foundation, current v3 profile contract, and
  relevant real-sample fingerprints.
- Profile scope is independent from HostContext; no implicit fallback or
  merged support claim.
- Parsing or packing an ELF does not prove it is launchable.
- The kernel and declared native interpreter remain responsible for loading
  original source bytes.

## Requirements

- Define class-specific boundaries for dynamic PIE, static PIE, ET_EXEC,
  shared object, sectionless/stripped shape, and interpreter.
- Add support only after the launcher invocation and runtime oracle exist.
- Compare baseline/wrapped status, stdout/stderr, argv/argv[0], environment,
  cwd, inherited descriptors, signals, declared files, and loader failures.
- Preserve anonymous memfd handoff and profile-matched launcher validation.

## Acceptance Criteria

- [x] Each broadened executable class has an exact acceptance rule and a paired
      rejected/negative boundary.
- [ ] Native baseline and wrapper behavior comparisons pass for the recorded
      runtime cells and retain complete evidence.
- [x] No ordinary shared object or unsupported executable class is treated as
      launchable solely because it parses.
- [x] Stale frame/profile mismatch continues to fail with stable diagnostics.
- [x] Outer compatibility rows remain separate from HostContext and parser
      support rows.
