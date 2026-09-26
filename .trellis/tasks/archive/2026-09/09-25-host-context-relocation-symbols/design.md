# Design: HostContext relocation, PLT/GOT, and symbol expansion

## Objective

Add common AArch64 dynamic relocation and symbol semantics to HostContext only
when their lookup, binding, target permission, and lifecycle behavior is
defined and observed through a real native oracle.

## Contract layers

1. Managed ELF model records the observed relocation/symbol metadata.
2. Static validator checks bounds, table ownership, alignment, writable target
   rules, dynamic flags, and feature-specific structural invariants.
3. HostContext capability metadata states what the adapter contract supports.
4. Native adapter preflight rejects unsupported combinations before loader
   handoff and clears output handles on failure.
5. Native fixture entry observes resolved values or dispatch behavior.
6. Manifest/evidence reports only the exact profile/runtime layer proven.

## Candidate family sequence

Use the real-sample histogram to select the first families. The native
real-sample CI artifact `real-samples-pr-36220307292` records `DT_GNU_HASH` and
PLT/JUMP_SLOT relocations in 20/20 identities and symbol-version metadata in
19/20 identities. The first PLT increment is deliberately narrower than generic PLT
support: a complete NOW-bound RELA PLT table containing only JUMP_SLOT for an
undefined weak, default-visible function, with no dependencies,
symbol-version tags, or non-preemptive-local flags. Existing RELATIVE/RELR and
GLOB_DAT status-29 semantics remain unchanged. Review of the current libc
dependency oracle also exposed a contract mismatch: it already carried
`DT_VERSYM`/`DT_VERNEED` imports while a rejected row claimed all version tags
were blocked. The dependency-side correction is a separate exact subfamily;
it does not widen dependency graph or search-path policy. Each family must
specify:

- relocation type and encoding;
- symbol index/name/version scope;
- binding time and conflict/weak/visibility rules;
- writable/aligned target and memory-protection requirements;
- dependency requirements;
- loader delegation boundary;
- failure status and pre-handoff guarantee;
- ABI capability/version impact.

### Selected weak undefined JUMP_SLOT contract

- `DT_JMPREL`, `DT_PLTRELSZ`, and `DT_PLTREL=DT_RELA` must each occur once;
  exact `DT_RELAENT=24`, `DT_SYMENT=24`, table bounds, file-backed symbol
  records, and writable/aligned targets are mandatory.
- Every record is `R_AARCH64_JUMP_SLOT`, with nonzero symbol index and symbol
  `STB_WEAK`, `STT_FUNC`, exact `st_other == STV_DEFAULT` with no processor-
  specific visibility flags, and `SHN_UNDEF`.
- The image has no `DT_NEEDED` and no version tags. `DT_SYMBOLIC`, non-preemptive
  local flags, PLT partial/duplicate/inconsistent forms, and all other symbol
  combinations are rejected. The lookup scope is the native loader's current
  global scope followed by this image's declared dependencies (none here).
- NOW is required by `DF_BIND_NOW` or `DF_1_NOW`; the adapter invokes `dlopen`
  using `RTLD_NOW`. Unresolved weak function address is zero. Only the native
  AArch64 glibc cell is claimed after the entry returns status 53.

### Single-system-libc import version requirements

- Keep `DT_VERDEF`/`DT_VERDEFNUM`, versioned exports, and versioned HostContext
  entry selection rejected; the declared entry name remains unversioned.
- Within the already accepted `DT_NEEDED libc.so.6` slice only, accept a
  complete `DT_GNU_HASH`/`DT_VERSYM`/`DT_VERNEED`/`DT_VERNEEDNUM` tuple.
  SysV `DT_HASH` alone or combined with `DT_GNU_HASH` remains outside this
  validated slice; `DT_SYMBOLIC` also remains rejected so lookup retains the
  native loader's ordinary dependency scope. Every `Verneed`
  `vn_file` must exactly match `libc.so.6`; records and
  auxiliary chains must be file-backed, bounded, monotonic, and terminate at
  declared counts. Require version 1, nonempty names, matching ELF name hashes,
  indices >= 2, and no weak-version flags. GNU-hash symbol counts, Verneed
  records, and aggregate auxiliaries use the native preflight cap of 1,048,576.
  Versioned imports paired with the
  other recognized musl/bionic libc SONAMEs remain rejected.
- The existing managed `VersionNeed` model remains the static observation
  owner; native preflight enforces the HostContext handoff boundary before
  loader creation. `RTLD_NOW` delegates libc version matching to the native
  loader. Missing host versions return `URP_STATUS_LOAD_FAILED`; no versioned
  entry lookup or additional dependency is introduced.
- The native AArch64 glibc fixture proves a `libc.so.6` versioned import and
  status-37 entry dispatch. Native mutations cover wrong `vn_file`, unmapped
  hash/VERSYM/Verneed/Aux pointers, GNU-chain truncation, a mapped-but-short
  VERSYM range, bad record/auxiliary links and hashes, weak-version flags,
  incomplete tuples, unsupported SysV hash and definitions, and output-handle
  clearing. No musl/bionic version-resolution claim follows from this cell.

Do not copy the same classification logic into managed C# and native C. The
managed model records facts; the native adapter enforces its runtime contract;
shared feature IDs and layout checks bind them.

## Fixtures and oracles

Use real linker output for positive fixtures, preferably with a minimal entry
that returns an observed value. Use bounded mutations for malformed and nearest-
negative cases, asserting no image handle, no entry call, and no side effect.
Retain separate glibc/musl/bionic evidence when behavior is runtime-specific.

## Rollback

If symbol scope or loader behavior remains ambiguous, keep the family modeled
or observed but rejected. Remove capability bits and acceptance branches while
retaining positive source fixtures as future evidence.
