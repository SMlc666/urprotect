# Runtime Difference Audit: glibc, musl, and bionic

## Executive Summary

This is a read-only audit of the TLS/ELF runtime boundary for task
`10-06-tls-relocation-runtime-matrix`. It consolidates the existing research
artifacts and targeted source inspections; it does not modify production code
or commit anything.

The repository currently has four distinct evidence layers:

1. **ABI and structural observation.** StructuralElf parses one bounded PT_TLS
   segment, template/zero-fill facts, dynamic/static TLS relocation records,
   and the AArch64 TLS relocation families. GNU AArch64 oracle fixtures cover
   the bounded instruction shapes for all five typed models.
2. **Managed semantic/layout acceptance.** The typed five-model semantic plan,
   snapshot, rewrite, and shared materialization/reparse checks establish a
   managed acceptance result. This does not establish loader behavior.
3. **Native HostContext adapter acceptance.** The C adapter accepts a much
   narrower image contract: PT_TLS is delegated to the system loader, and the
   dynamic relocation validator admits the relative forms plus
   `R_AARCH64_TLS_TPREL64` and a separately bounded PLT subset. Dynamic TLS is
   explicitly rejected before memfd creation on non-glibc lanes.
4. **Promoted transformed runtime evidence.** Exactly one transformed TLS row is
   promoted: `initial-exec x host-context-entry x glibc x current-thread`. The
   existing native initial-exec worker row is glibc-only baseline/adapter
   evidence, not proof of transformed worker support. Musl and bionic have
   separate general runtime/adapter evidence, but no promoted transformed TLS
   row.

### High-severity finding

There is a cross-layer Android packed-relocation constant mismatch. The native
HostContext validator rejects the canonical eight Android packed relocation
keys using values `0x6000000f`, `0x60000010`, `0x60000011`, `0x60000012`,
`0x6fffe000`, `0x6fffe001`, `0x6fffe003`, and `0x6fffe005`
([host_image_validation.c](/root/urprotect/native/urprotect-runtime/host_image_validation.c:85)).
The managed `ElfConstants` table has seven entries, uses `0x6000000e` for
`DT_ANDROID_REL`, uses `0x60000013/14/15` for Android RELR metadata, and omits
`DT_ANDROID_RELRCOUNT` ([ElfTypes.cs](/root/urprotect/src/UrProtect.Core/StructuralElf/ElfTypes.cs:88)).
`ProfileMaterializationPolicies` uses those managed values for HostContext
preflight ([ProfileMaterializationPolicies.cs](/root/urprotect/src/UrProtect.Core/Application/Rehydration/ProfileMaterializationPolicies.cs:127)).
Therefore a real bionic image carrying canonical Android packed tags can be
recognized/rejected differently by managed preflight and the native adapter.
This is a correctness and promotion-gate risk, not evidence that bionic TLS is
supported.

## Promotion contract

The complete transformed TLS scope remains in this task and is keyed by
`model × profile × runtime × lifecycle` across local-exec, initial-exec,
local-dynamic, general-dynamic, TLSDESC; `outer-execveat` and
`host-context-entry`; applicable current-thread/registered-worker lifecycles;
and glibc, musl, and bionic. Musl and bionic are required rows, not optional
follow-up scope.

A row is promoted only when its own managed rewrite/materialization, loader
handoff, behavior comparison, PT_TLS template/zero-fill, per-thread values,
constructor/destructor/worker/release order, source/protected/native artifact
hashes, toolchain/runtime/loader identity, first-failure stage, and rollback
witness are retained. Missing capabilities are row-local
`environment-unavailable` results and never inherit glibc evidence. The only
currently promoted transformed row is `initial-exec x host-context-entry x glibc
x current-thread`; musl/bionic and all other model/profile/lifecycle rows remain
unpromoted until their independent evidence passes.

The four evidence layers stay separate: StructuralElf observation, managed
semantic/layout acceptance, native HostContext adapter acceptance, and
transformed runtime promotion. The six-cell `fixtures/runtime-matrix.json`
covering set is environment/loader evidence, not a TLS promotion matrix.

## Prerequisite decisions and probes

- The high-severity managed/native Android packed-relocation tag mismatch is a
  prerequisite correction/probe. Reconcile managed `ElfTypes` and
  `ProfileMaterializationPolicies` with native `host_image_validation.c`, then
  probe each canonical tag independently for matching rejection, zero handle,
  and no publication before any bionic transformed row advances.
- Run a managed/native PT_TLS predicate-parity probe for count, range/size,
  alignment, flags, owning `PT_LOAD`, and template/zero-fill. Resolve any
  intentional difference as a named layer boundary before promotion.
- Preserve the sectionless common-contract decision: StructuralElf/managed
  parsing may observe or accept sectionless images and glibc has a positive
  adapter oracle, but bionic requires section headers. The common transformed
  three-runtime shape is sectioned; bionic sectionless rejection is a
  loader-specific boundary, not support.
- Keep worker lifecycle independent from current-thread evidence. Claimed
  worker rows retain creation/join, TLS teardown, constructor/destructor,
  release, and image-destruction order; missing worker capability is an
  explicit feature-specific environment result.


| Inventory | Count | Evidence |
|---|---:|---|
| Typed TLS access models | 5 | `LocalExec`, `InitialExec`, `LocalDynamic`, `GeneralDynamic`, `TlsDesc` in [TlsSemanticModels.cs](/root/urprotect/src/UrProtect.Core/SemanticPlanning/TlsSemanticModels.cs:7) |
| Typed TLS relocation families | 5 | `Tprel`, `GotTprel`, `Dtpmod`, `Dtprel`, `TlsDesc` in [TlsSemanticModels.cs](/root/urprotect/src/UrProtect.Core/SemanticPlanning/TlsSemanticModels.cs:18) |
| TLS address-expression kinds | 4 | Thread-pointer, module-relative, resolver-returned, descriptor-mediated in [TlsSemanticModels.cs](/root/urprotect/src/UrProtect.Core/SemanticPlanning/TlsSemanticModels.cs:27) |
| Managed AArch64 TLS relocation constants | 66 | Values 512-573 plus 1028-1031 in [ElfTypes.cs](/root/urprotect/src/UrProtect.Core/StructuralElf/ElfTypes.cs:119) |
| Managed Android packed-tag constants | 7 | [ElfTypes.cs](/root/urprotect/src/UrProtect.Core/StructuralElf/ElfTypes.cs:88) |
| Native Android packed-tag rejection constants | 8 | Four legacy packed REL/RELA tags, three RELR table tags, and RELR count in [host_image_validation.c](/root/urprotect/native/urprotect-runtime/host_image_validation.c:85) |
| Canonical Android packed tags missing/wrong in managed table | 6 | Five wrong numeric values plus missing `DT_ANDROID_RELRCOUNT`; two managed legacy RELA values happen to match |
| Evidence-checker TLS models | 5 | [check-protected-image-evidence.py](/root/urprotect/scripts/check-protected-image-evidence.py:15) |
| Evidence-checker runtime lanes | 3 | `glibc`, `musl`, `bionic` in [check-protected-image-evidence.py](/root/urprotect/scripts/check-protected-image-evidence.py:171) |
| Evidence-checker profiles | 2 | `outer-execveat`, `host-context-entry` in [check-protected-image-evidence.py](/root/urprotect/scripts/check-protected-image-evidence.py:16) |
| Evidence-checker lifecycle values | 3 | `current-thread`, `registered-worker`, `not-run` in [check-protected-image-evidence.py](/root/urprotect/scripts/check-protected-image-evidence.py:18) |
| Runtime covering-set cells | 6 | Two glibc cells, two musl cells, one bionic cell, one native page probe in [runtime-matrix.json](/root/urprotect/fixtures/runtime-matrix.json:27) |
| Runtime tiers | 3 | `pr`, `nightly`, `release` in [runtime-matrix.json](/root/urprotect/fixtures/runtime-matrix.json:4) |
| TLS-related manifest feature rows | 3 | Managed transformed TLSIE, native PT_TLS, and threaded initial-exec rows in [manifest.json](/root/urprotect/fixtures/manifest.json:370) |
| Promoted transformed TLS rows | 1 | `runtime.host-context.protected-image-tls-initial-exec`, glibc/current-thread only in [manifest.json](/root/urprotect/fixtures/manifest.json:370) |

The local environment observed during the audit is native `aarch64` with a
4096-byte page size, GCC 15.2.0/binutils 2.46 AArch64 tools, and no
`musl-gcc`, Docker, or Podman. This means local reproduction can cover GNU
shape/structural probes and native glibc adapter behavior, but not the locked
musl producer or the Termux/bionic container lane. The lane scripts explicitly
require those capabilities ([run-bionic-fixture.sh](/root/urprotect/scripts/run-bionic-fixture.sh:14),
[run-tls-host-context-rehydration-e2e.sh](/root/urprotect/scripts/run-tls-host-context-rehydration-e2e.sh:23)).

## Runtime Difference Matrix

### ELF header and image identity

| Topic | glibc lane | musl lane | bionic/Android lane | Classification |
|---|---|---|---|---|
| Required managed/native identity | ELF64, little-endian, AArch64, ET_DYN for HostContext | Same bounded ET_DYN shape for the selected loader fixtures | ET_DYN, AArch64, `/system/bin/linker64` for the locked Termux fixture | Shared image contract; loader-specific interpreter evidence |
| Native header validator | Checks ELF magic/class/data/version, ET_DYN, machine 183, `e_ehsize=64`, `e_phentsize=56`, and bounded program headers | Same C validator if the adapter is built there; musl runtime is a separate launcher/loader execution cell | Same adapter preflight, then bionic loader; bionic direct-linker identity is retained | Adapter contract, not generic libc support |
| Sectionless ET_DYN | Positive HostContext oracle: managed parser accepts `e_shoff=e_shnum=e_shstrndx=0`, and glibc self-test dispatches it | No promoted sectionless HostContext row | API 26+ bionic rejects the mutated sectionless combination before dynamic metadata is consulted; the bionic lane skips it and records a boundary marker | Loader-specific incompatibility; do not weaken StructuralElf |
| Section-header entry size | Not needed by the sectionless glibc path | Not separately promoted | Bionic fixture history required preserving the ELF64 section entry size when sections are retained; the current lane records this as part of bionic build evidence | Bionic loader behavior |
| `PT_INTERP` | HostContext transformed image is interpreter-free and loaded through sealed memfd/dlopen; outer glibc fixtures use `/lib/ld-linux-aarch64.so.1` | Runtime matrix uses `/lib/ld-musl-aarch64.so.1` and pinned musl loader paths | Locked fixture requires `/system/bin/linker64` and validates direct linker identity | Independent loader identity; no cross-runtime substitution |

Evidence for the sectionless split is explicit in the native test:
non-bionic builds mutate section-header fields and require status 23, while
bionic builds emit `HostContext self-test: sectionless image skipped on bionic;
loader requires section headers` ([host_context_self_test.c](/root/urprotect/native/urprotect-runtime/host_context_self_test.c:913)).
The bionic evidence checker requires both the structured boundary record and the
log marker ([check-runtime-matrix-evidence.py](/root/urprotect/scripts/check-runtime-matrix-evidence.py:152)).
The managed positive is independently covered by
`AcceptsSectionlessPieUsingProgramHeaders` ([ElfParserTests.cs](/root/urprotect/tests/UrProtect.Core.Tests/Structural/ElfParserTests.cs:26)).

### PT_TLS template, zero-fill, and ownership

| Topic | Managed StructuralElf | Native HostContext adapter | Runtime implication |
|---|---|---|---|
| Count | Rejects more than one PT_TLS; requires a non-empty memory range | The native loop validates each PT_TLS header but does not establish the managed exactly-one/non-empty semantic rule | A multi-PT_TLS or empty-PT_TLS probe can expose policy drift |
| Size/range | Requires `p_filesz <= p_memsz`, bounded file template, and checked virtual range | Global program-header checks require `p_memsz >= p_filesz`, file range in image, and checked alignment/congruence | Both reject basic malformed sizes, but managed diagnostics are more specific |
| Alignment | Requires power-of-two alignment and `p_offset % p_align == p_vaddr % p_align` | Same generic program-header checks in [host_image_validation.c](/root/urprotect/native/urprotect-runtime/host_image_validation.c:1565) | Equivalent for the current bounded geometry |
| Permissions | PT_TLS must be readable, non-executable, and have no unknown flags; if writable, owner load must be writable | PT_TLS must be non-executable and must lie in a writable PT_LOAD; it does not require PT_TLS `PF_R` explicitly | Managed/native acceptance can diverge on `PF_R`/`PF_W` combinations |
| Owning PT_LOAD | Exactly one owner with matching file/virtual mapping; an observed Go zero-file marker with `p_vaddr=0`, `p_filesz=0`, a bounded `p_offset` (including the image end), and no owner is retained with owner `-1` for observation only | Uses a writable-load containment check; no equivalent ownerless observation contract | Real-sample observation is separate from transform eligibility |
| Template/zero-fill | `TlsSegmentFacts` owns initialized bytes and exposes `MemorySize - FileSize` as zero-fill ([TlsFacts.cs](/root/urprotect/src/UrProtect.Core/StructuralElf/TlsFacts.cs:6)) | System loader owns allocation/initialization; native self-test only accepts the narrow adapter PT_TLS slice | Runtime evidence must compare both initialized bytes and zero-fill |

The managed ownerless exception is deliberately narrow: only
`p_vaddr=0`, `p_filesz=0`, a bounded `p_offset`, and no owning load are
retained for structural observation. Go's `micro` sample uses a nonzero
`p_offset` at the image end; the parser retains that fact while projection
still fails with `TlsBindingUnresolved` ([ElfTlsParser.cs](/root/urprotect/src/UrProtect.Core/StructuralElf/ElfTlsParser.cs:160),
[ElfParserTests.cs](/root/urprotect/tests/UrProtect.Core.Tests/Structural/ElfParserTests.cs:274)).
Nonzero virtual addresses and unbounded offsets remain malformed.
This is compatible with the task's rule that a structurally observed real sample
is not automatically transformable.

### Relocation and dynamic metadata behavior

| Topic | Managed pipeline | Native HostContext adapter | Classification |
|---|---|---|---|
| AArch64 TLS instruction relocations | Recognizes 66 ABI constants across GD, LD, IE, LE, TLSDESC, and loader-owned 64-bit forms; sequence context determines model | Does not apply or rewrite TLS instruction relocations | Managed semantic/layout scope |
| Loader-owned TLS words | Models `DTPMOD64`, `DTPREL64`, `TPREL64`, and `TLSDESC` with typed ownership | Native dynamic RELA validator admits only `R_AARCH64_TLS_TPREL64` as a symbolic TLS relocation ([host_image_validation.c](/root/urprotect/native/urprotect-runtime/host_image_validation.c:456)) | Native adapter is initial-exec-only |
| RELATIVE/RELR | Structural parser models RELR and raw Android packed tables; HostContext materialization policies reject unsupported Android tags | Native adapter accepts checked AArch64 RELATIVE/RELR through the system loader | Separate validated relocation feature |
| Legacy `DT_REL` | HostContext profile preflight rejects it | Native validator rejects it before loader handoff | Stable rejected boundary |
| Android packed REL/RELA/RELR | Parser preserves bounded raw tables using the managed constants, but the constants do not match the native canonical set | Native rejects all eight canonical Android packed tags before memfd/dlopen ([host_image_validation.c](/root/urprotect/native/urprotect-runtime/host_image_validation.c:1227)) | **High-severity managed/native tag mismatch** |
| PLT RELA | StructuralElf bounds RELA/PLT tuples and records ownership | Native admits only the exact weak-undefined `JUMP_SLOT` subset with immediate binding and no arbitrary dependency/version behavior | Adapter-specific accepted subset |
| Symbol versions | Managed parser models version metadata; HostContext profile rejects version definitions and only accepts its separately bounded libc import requirement | Native rejects version definitions and out-of-slice version tables | No generic versioned entry claim |
| RPATH/RUNPATH/TEXTREL | HostContext policy rejects these tags | Native validator rejects them before loader handoff | Stable rejected boundaries |

The native dynamic validator's symbolic set is visible at
[host_image_validation.c](/root/urprotect/native/urprotect-runtime/host_image_validation.c:456):
`ABS64`, `GLOB_DAT`, and `TLS_TPREL64` are the only symbolic types in the
ordinary RELA path. Any other non-relative relocation is rejected by the
following predicate ([host_image_validation.c](/root/urprotect/native/urprotect-runtime/host_image_validation.c:486)).

The managed parser has a different responsibility: it bounds and preserves
Android packed bytes without decoding them ([ElfParser.cs](/root/urprotect/src/UrProtect.Core/StructuralElf/ElfParser.cs:767)).
That behavior is valid only if the dynamic-tag constants are canonical and the
profile policy rejects the resulting table consistently. The managed/native canonical tag set is now shared by the managed collection and native header, with the one-tag rejection probe retained under the prerequisite evidence root.

### TLS model and lifecycle behavior

| Model/lifecycle | Managed semantic status | glibc evidence | musl evidence | bionic evidence |
|---|---|---|---|---|
| Local-exec | Typed model and bounded instruction/layout fixtures; no transformed runtime row | No promoted transformed row | No transformed row | No transformed row |
| Initial-exec current thread | Typed model, real TLSIE transformed producer/re-hydration lane | **Promoted transformed row**, status 43, template/zero-fill/teardown observed | No transformed row | No transformed row |
| Initial-exec registered worker | Typed/native lifecycle contract | Native glibc worker and teardown evidence; current row is initial-exec and opt-in | Explicitly outside row | Explicitly outside row |
| Local-dynamic | Typed exact TLSLD semantic/layout slice with `__tls_get_addr` and DTPMOD/DTPREL ownership; no runtime promotion | No transformed runtime row | No transformed runtime row | No transformed runtime row |
| General-dynamic | Typed model/sequence contract; no transformed runtime row | No transformed runtime row | No transformed runtime row | No transformed runtime row |
| TLSDESC | Exact four-marker managed producer/layout slice; no transformed runtime row | No transformed runtime row | No transformed runtime row | No transformed runtime row |
| Dynamic TLS negative | Native dynamic fixture is rejected before memfd creation on non-glibc; adapter-level negative on glibc as well | Dynamic TLS remains outside current HostContext contract | No callback capability and explicit rejection | No callback capability and explicit rejection |

The five models and their five relocation families are typed rather than string
aliases ([TlsSemanticModels.cs](/root/urprotect/src/UrProtect.Core/SemanticPlanning/TlsSemanticModels.cs:7)).
The exact GNU sequence oracles and managed status are retained in:

- [aarch64-tlsle-movw-g1-g0nc-oracle.md](/root/urprotect/.trellis/tasks/10-06-tls-relocation-runtime-matrix/research/aarch64-tlsle-movw-g1-g0nc-oracle.md)
- [aarch64-tlsle-ldst32-oracle.md](/root/urprotect/.trellis/tasks/10-06-tls-relocation-runtime-matrix/research/aarch64-tlsle-ldst32-oracle.md)
- [aarch64-tlsie-movw-g1-g0nc-oracle.md](/root/urprotect/.trellis/tasks/10-06-tls-relocation-runtime-matrix/research/aarch64-tlsie-movw-g1-g0nc-oracle.md)
- [aarch64-tlsie-adr-ld64-oracle.md](/root/urprotect/.trellis/tasks/10-06-tls-relocation-runtime-matrix/research/aarch64-tlsie-adr-ld64-oracle.md)
- [aarch64-tlsie-ld-gottprel-prel19-oracle.md](/root/urprotect/.trellis/tasks/10-06-tls-relocation-runtime-matrix/research/aarch64-tlsie-ld-gottprel-prel19-oracle.md)
- [aarch64-tlsld-oracle.md](/root/urprotect/.trellis/tasks/10-06-tls-relocation-runtime-matrix/research/aarch64-tlsld-oracle.md)
- [aarch64-tlsdesc-oracle.md](/root/urprotect/.trellis/tasks/10-06-tls-relocation-runtime-matrix/research/aarch64-tlsdesc-oracle.md)

The glibc-only worker capability is compile/runtime gated in
[host_adapter.c](/root/urprotect/native/urprotect-runtime/host_adapter.c:248):
thread callbacks are installed only under `__GLIBC__` and after a non-null
`gnu_get_libc_version()`. The non-glibc test requires absent callbacks and
rejects dynamic TLS without attempting memfd creation
([host_context_thread_adapter_test.c](/root/urprotect/native/urprotect-runtime/host_context_thread_adapter_test.c:69)).
The manifest explicitly excludes dynamic TLS, musl, and bionic threaded claims
([manifest.json](/root/urprotect/fixtures/manifest.json:485)).

## Runtime Evidence Classification

### Validated independent facts

- Native AArch64 ELF identity and bounded PT_LOAD/load-map behavior.
- GNU AArch64 TLS relocation constants and linker-produced sequence shapes.
- Managed five-model semantic records, typed address expressions, relocation
  pairing, snapshot coverage, and shared layout/materialization checks.
- Native glibc HostContext initial-exec adapter behavior, including current
  thread and the separate registered-worker lifecycle.
- Native bionic/Termux HostContext adapter handoff, sealed memfd behavior,
  `/system/bin/linker64` identity, and the sectionless-loader boundary when the
  locked lane is run.
- Runtime matrix ELF alignment and loader identity cells for glibc/musl/bionic
  when their required environments are available.

### Not promoted by current evidence

- Transformed musl TLS for any model or lifecycle.
- Transformed bionic TLS for any model or lifecycle.
- Transformed glibc local-exec, local-dynamic, general-dynamic, or TLSDESC.
- Transformed registered-worker TLS lifecycle.
- Generic Android packed relocation support.
- Generic symbol-version, path-search, writable-text relocation, or arbitrary
  dependency support in HostContext.

The transformed TLS runner hard-codes the current promoted row to glibc,
initial-exec, current-thread, and `host-context-entry`
([run-tls-host-context-rehydration-e2e.sh](/root/urprotect/scripts/run-tls-host-context-rehydration-e2e.sh:32)).
The evidence checker intentionally keeps `accepted-and-runs`,
`environment-unavailable`, and `runtime-failure` distinct and requires complete
publication before any runtime result ([check-protected-image-evidence.py](/root/urprotect/scripts/check-protected-image-evidence.py:275)).

## Findings and Focused Probe Recommendations

### F1: Android packed dynamic-tag mismatch (resolved)

**Classification:** resolved managed/native contract mismatch; retained as a permanent negative boundary.

**Evidence:** canonical eight-entry managed collection in [ElfTypes.cs](/root/urprotect/src/UrProtect.Core/StructuralElf/ElfTypes.cs:88), shared native definitions in [android_packed_relocation_tags.h](/root/urprotect/native/urprotect-runtime/android_packed_relocation_tags.h), managed HostContext rejection in [ProfileMaterializationPolicies.cs](/root/urprotect/src/UrProtect.Core/Application/Rehydration/ProfileMaterializationPolicies.cs:138), and native rejection in [host_image_validation.c](/root/urprotect/native/urprotect-runtime/host_image_validation.c:85).

**Focused probe result:** `.artifacts/tls-prerequisites/<tier>/android-packed-tags.json` retains all eight one-tag mutations. The managed policy test and native probe agree on rejection, zero handle, and no publication; raw-table parsing remains observation-only.

### F2: PT_TLS permission/ownership policy parity (resolved boundary)

**Classification:** resolved by an explicit HostContext profile predicate and retained parity evidence.

**Evidence:** managed PT_TLS checks require readable/non-executable flags and
exactly one mapped owner ([ElfTlsParser.cs](/root/urprotect/src/UrProtect.Core/StructuralElf/ElfTlsParser.cs:88));
native PT_TLS checks require non-executable and a writable owner load
([host_image_validation.c](/root/urprotect/native/urprotect-runtime/host_image_validation.c:1602)).

**Focused probe result:** `.artifacts/tls-prerequisites/<tier>/pt-tls-predicate-parity.json` retains six mutations: baseline, executable TLS, read-only owner, empty memory, filesz/memsz mismatch, and non-power-of-two alignment. The common sectioned HostContext handoff predicate is now explicit; broader StructuralElf observation remains separate.

### F3: Bionic section-header requirement is loader-specific

**Classification:** known compatibility boundary; not a parser defect.

**Evidence:** managed parser accepts sectionless program-header-only images
([ElfParserTests.cs](/root/urprotect/tests/UrProtect.Core.Tests/Structural/ElfParserTests.cs:26));
glibc self-test executes the mutated image; bionic skips it and requires the
boundary marker ([host_context_self_test.c](/root/urprotect/native/urprotect-runtime/host_context_self_test.c:913)).

**Focused probe:** retain two otherwise byte-identical ET_DYN fixtures: one
with valid section headers and one with `e_shoff=e_shnum=e_shstrndx=0`. Run both
through glibc `dlopen`, musl's pinned loader, and bionic `/system/bin/linker64`.
Record loader status, stderr, and header bytes. Do not classify bionic's
sectionless rejection as a managed structural rejection.

### F4: Native adapter is initial-exec-only despite broad managed model names

**Classification:** high scope risk; semantic support and runtime support are
separate.

**Evidence:** native symbolic relocation set admits `TLS_TPREL64` only
([host_image_validation.c](/root/urprotect/native/urprotect-runtime/host_image_validation.c:456));
PT_TLS comment explicitly calls the slice static initial-exec
([host_image_validation.c](/root/urprotect/native/urprotect-runtime/host_image_validation.c:1602));
dynamic TLS is rejected before memfd on non-glibc adapters
([host_context_thread_adapter_test.c](/root/urprotect/native/urprotect-runtime/host_context_thread_adapter_test.c:73));
the transformed matrix promotes only the independently verified glibc initial-exec control row and records every other row independently
([run-tls-host-context-rehydration-e2e.sh](/root/urprotect/scripts/run-tls-host-context-rehydration-e2e.sh:122)).

**Focused probe:** for each of the five models, retain baseline, transformed
candidate, loader handoff result, per-thread value, zero-fill value, teardown
markers, and source/transformed/artifact hashes. Execute each independently on
all three lanes. A missing toolchain/runtime must produce a model-specific
`environment-unavailable` row; it must not inherit the glibc initial-exec pass.

### F5: Worker lifecycle is glibc-only and must remain separate

**Classification:** known runtime/lifecycle boundary.

**Evidence:** callbacks are compiled and advertised only under `__GLIBC__`
([host_adapter.c](/root/urprotect/native/urprotect-runtime/host_adapter.c:248),
[host_adapter.c](/root/urprotect/native/urprotect-runtime/host_adapter.c:496));
release joins workers before `dlclose` ([host_adapter.c](/root/urprotect/native/urprotect-runtime/host_adapter.c:361));
manifest constraints exclude musl and bionic threaded claims
([manifest.json](/root/urprotect/fixtures/manifest.json:485)).

**Focused probe:** use one fixture with initialized TLS, `.tbss` zero-fill,
constructor/destructor markers, pthread-key teardown, and a worker that
outlives entry. Require explicit worker join and automatic release join. Run
negative cases for missing capability, callback omission, foreign image handle,
join failure, release failure, and dynamic TLS. Keep lifecycle evidence separate
from current-thread model evidence.

### F6: Runtime matrix is an environment covering set, not a TLS promotion matrix

**Classification:** evidence interpretation risk.

**Evidence:** six covering cells are alignment/loader/runtime cells
([runtime-matrix.json](/root/urprotect/fixtures/runtime-matrix.json:27));
only one feature row carries transformed TLS evidence
([manifest.json](/root/urprotect/fixtures/manifest.json:370));
container cells validate direct baseline/copy behavior and loader identity
([check-runtime-matrix-evidence.py](/root/urprotect/scripts/check-runtime-matrix-evidence.py:305)),
not transformed TLS behavior.

**Focused probe:** add a second matrix keyed by
`model × profile × runtime × lifecycle`, or an equivalent explicit projection,
with a row for every claimed model. Require source/transformed/artifact hashes,
PT_TLS facts, loader/toolchain identity, first-failure stage, publication
result, rollback result, and lifecycle markers. Keep the existing six-cell
covering set as environment evidence rather than using it as proof of TLS
transformation support.

### F7: Local environment cannot execute the complete three-runtime audit

**Classification:** environment limitation; no support inference.

**Evidence:** local facts were native AArch64, 4096-byte pages, GNU
cross-toolchain present, `musl-gcc` absent, Docker absent, Podman absent. The
bionic script requires Docker/native Linux arm64 and forbids emulator fallback
([run-bionic-fixture.sh](/root/urprotect/scripts/run-bionic-fixture.sh:14));
the musl matrix cells require the pinned source-built toolchain and loader
([runtime-matrix.json](/root/urprotect/fixtures/runtime-matrix.json:69)).

**Focused probe:** run the existing native AArch64 CI producers for musl 1.2.4,
Alpine musl 1.2.5, and Termux/bionic. Preserve exact image/package/toolchain
hashes, direct-loader output, host/container page sizes, baseline/copy output,
and failure classification. Report unavailable environments explicitly.

## Recommended Probe Order

1. Correct and cross-check the eight Android packed dynamic-tag constants in a
   fixture-only probe; this is the only finding that can cause immediate
   managed/native disagreement before loader handoff.
2. Run the PT_TLS predicate matrix across managed parser, native preflight, and
   each available loader; settle readable/writable/ownerless policy.
3. Run sectioned versus sectionless ET_DYN images through glibc, musl, and
   bionic, retaining loader-specific statuses and logs.
4. Execute the transformed initial-exec control row on each runtime where the
   environment exists, then add model-specific local-exec, LD/GD, and TLSDESC
   rows only after semantic/layout validation passes.
5. Add worker lifecycle rows independently from current-thread rows and retain
   teardown/release ordering.
6. Re-run the complete evidence checker with a closed hash manifest; no runtime
   row is promoted from a different libc or loader.

## Residual Risks

- The Android packed-tag mismatch is resolved in the current tree by the shared native header, canonical managed constants, profile rejection set, and eight-row prerequisite probe.
- Native HostContext PT_TLS acceptance is intentionally loader-owned and narrower
  than the managed five-model semantic contract; successful native adapter
  loading does not prove transformed TLS semantics.
- Bionic section-header requirements and musl loader/toolchain availability are
  environment-specific. A glibc result cannot fill either gap.
- The current runtime covering set exercises loader identity, alignment, and
  baseline/copy execution; it does not by itself establish transformed TLS
  behavior for all model/profile/runtime/lifecycle combinations.
- The follow-up implementation now retains managed/native probe artifacts under `.artifacts/tls-prerequisites/<tier>` and the transformed four-dimensional matrix under `.artifacts/tls-runtime/<tier>`.
