# Technical design: unified current protection workflow

## Workflow contract

```text
Current CLI request
  -> ProtectionApplicationRequest
  -> StructuralElfIndex
  -> SelectedFunctionAnalysis
  -> SemanticRewritePlan / ProtectionPlan
  -> ProfileAwareElfLayoutPlan
  -> ProfileAwareNativeImageMaterializer
  -> Reparse + structural/profile validation
  -> Atomic artifact/native publication
  -> Current report/evidence projection
```

`protect`, `protect-image`, and `rehydrate-image` call the same application workflow and typed contracts. They differ only in which stage results they publish, not in how transformation or materialization is implemented.

## Profile ownership

### OuterExecveat

- Validates standalone executable/PIE invariants.
- Materializes the current native image through the generic outer layout policy.
- Publishes a profile-bound native descriptor.
- Uses the existing anonymous memfd/`execveat(AT_EMPTY_PATH)` oracle.

### HostContextEntry

- Validates current AArch64 `ET_DYN` entry-image invariants, no process interpreter, bounded entry symbol, executable entry mapping, and native preflight subset.
- Consumes the same current Protected Image operations, semantic plan, address map, and physical layout planner as the outer profile.
- Uses a HostContext-specific materializer policy for profile metadata and output validation, not a second byte writer.
- Binds current v3 HostContext ABI version, required capabilities, entry symbol, source/artifact digests, and profile marker before publication.
- Runs the native sealed-memfd/system-loader HostContext handoff oracle against the rehydrated output and records exactly-once entry status, release order, loader identity, and hashes.
- Never invokes or reinterprets the outer `execveat` materializer.

## Ownership split

- `ProtectionWorkflow`: orchestration and typed result aggregation only.
- `ProtectionPlanner`: selectors, passes, selected-function analysis, semantic/protection plan.
- `ElfLayoutPlanner`/`ElfLayoutMaterializer`: physical placement and byte emission, shared by both profiles.
- `ProfileMaterializer`: profile-specific invariants and adapter selection, not duplicate emission.
- `ArtifactPublisher`: atomic role/stage/native/report publication and rollback.
- `HostContextHandoff`: native oracle adapter/evidence projection; no ELF transformation logic.

## Failure behavior

Every stage returns deterministic diagnostics. Profile mismatch, missing entry, unsupported profile metadata, layout failure, output reparse failure, or handoff failure prevents final publication and removes staged files. The result records first-failure stage and no stale role/evidence is left behind.

## No-history rule

The workflow references only the current contract produced by G0. It has no migration oracle, compatibility alias, alternate writer, retired frame version, or historical test data. New semantic domains must add operations to the one current artifact model rather than introducing a sibling artifact format.
