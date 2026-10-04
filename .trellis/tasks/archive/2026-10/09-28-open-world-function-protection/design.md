# Technical design

## 1. Design goals and boundaries

This task has two coupled but independently measurable products:

1. an open-world AArch64 compatibility path that preserves unknown ELF data and
   delegates execution to the declared native runtime whenever the selected
   launch profile can preserve the required semantics; and
2. an opt-in function protection path that transforms only explicitly selected
   functions through control-flow flattening followed by register permutation.

The compatibility path must not require function analysis. The protection path
must not change an unselected function or silently widen the selection. A
selected-function failure aborts the complete protection operation before any
output is published.

HostContext remains a separate, intentionally narrower in-process contract.
The full-corpus nightly claim concerns ordinary executable baseline and outer
wrapper execution, not automatic HostContext conversion of ordinary programs.

## 2. Proposed package boundaries

### Managed core

Add the following project-owned boundaries under `src/UrProtect.Core`:

- `Elf/Symbols/`: section-symbol and dynamic-symbol inventory, symbol-table
  identity, exact function ranges, aliases, and selector resolution.
- `Aarch64/Ir/`: project-owned instruction, operand, register, machine-state,
  and control-flow records. AsmStone types stop at the adapter boundary.
- `Aarch64/ControlFlow/`: function discovery, basic blocks, CFG edges,
  uncertainty barriers, and CFG invariants.
- `Aarch64/State/`: register classes/views, implicit effects, flags, ABI
  boundaries, memory effects, pressure, interference, and spill planning.
- `Protect/`: selection, pass contracts, flattening, register permutation,
  composition, and per-function outcomes.
- `Rewrite/`: code placement, branch/PC-relative repair, relocation ownership,
  ELF program/section metadata updates, and atomic output publication.

`ElfPackService` remains responsible for packaging an already validated image;
the new protection service produces a rewritten ELF before optional packaging.
The no-op pipeline remains byte-preserving and is not reused as a writer.

### Integration scripts and fixtures

- `scripts/run-protection-e2e.sh` owns the common original/protected behavior
  comparison for the three runtime profiles.
- `scripts/run-real-sample-matrix.sh` gains runtime-closure acquisition,
  baseline and outer-wrapper execution, shard support, and schema-3 evidence.
- `fixtures/real-samples/runtime-closures.json` (or an equivalent separate
  locked manifest) owns exact package/rootfs closure inputs and hashes.
- `fixtures/real-samples/protection-policy.json` owns only explicit function
  selectors and transform requests. It never means “all functions”.

## 3. Compatibility architecture

### Result semantics

The real-sample schema is upgraded so static validation cannot be confused with
execution:

- `validated`: parser/fingerprint/structural validation passed; no process ran.
- `accepted-and-runs`: the declared process oracle ran successfully.
- `runtime-failure`: the product or sample ran and failed.
- `environment-unavailable`: the required locked runtime/isolation capability
  was unavailable.
- `unexpected-rejection` / `unexpected-acceptance`: actual and policy results
  disagree.
- `not-applicable`: reserved for layers whose contract genuinely does not
  apply, such as HostContext on a normal executable or function protection when
  no explicit selector exists.

The result schema retains distinct `static`, `baseline`, `outerWrapper`, and
`hostContext` records and adds a separate `functionProtection` record (or
equivalent nested object) for explicit selector outcomes. Existing aggregate
and evidence validators are upgraded together; no report may use
`accepted-and-runs` for static-only success.

### Runtime-closure model

Every real-sample identity receives a locked execution policy containing:

- runtime family and loader path;
- immutable base rootfs/image identity;
- exact package archive list with version, URL/path, size, and SHA-256;
- dependency-closure manifest generated from the pinned distro/package index;
- artifact path and a bounded invocation argv/cwd/environment policy;
- expected exit/status/stream and declared side-effect observations;
- maximum wall time, address space, process count, output, and temporary space.

The closure builder downloads only the locked archives into `RUNNER_TEMP`,
verifies every digest, and extracts them into a private runtime root. It does
not consult ambient runner libraries for the target process.

The first closure families are:

- **glibc:** pinned Debian Bookworm ARM64 base/rootfs plus exact `.deb`
  dependency archives for the 78 declared identities. Packages are extracted
  into the rootfs using bounded `dpkg-deb`/archive operations; package scripts
  are not executed as part of evidence construction.
- **musl:** the existing pinned Alpine minirootfs for BusyBox and a pinned
  Alpine 3.22 ARM64 base/rootfs plus exact APK dependency archives for the 20
  APK identities. APK metadata and archive hashes are checked before use.
- **bionic:** the existing digest-pinned native ARM64 Termux container and a
  locked Termux package closure containing Node.js and all runtime dependencies.
  The container lane remains the only first-phase bionic oracle and runs
  through `/system/bin/linker64`.

Closure generation is a separate reproducibility step from sample execution.
The generated lock is committed or retained as a reviewed manifest; raw
archives/rootfs trees remain temporary and are never uploaded as evidence.

### Baseline and outer oracle

For each identity the runner:

1. acquires and verifies the source archive and closure;
2. extracts the declared artifact and checks its fingerprint;
3. executes the original artifact with the locked argv in a networkless,
   read-only, bounded root;
4. invokes the managed packer with a profile-matched launcher;
5. executes the packed result in the same runtime closure;
6. compares exit status, stdout, stderr, signals, cwd/environment observations,
   and declared file side effects; and
7. removes raw input and records only normalized evidence and hashes.

The native launcher is extended to recognize `/system/bin/linker64` as a
declared bionic interpreter. The managed packer and launcher retain nearest
negative tests for malformed, duplicate, missing, and unrecognized interpreters.

For path-sensitive images (`RPATH`, `RUNPATH`, `$ORIGIN`, or equivalent
metadata), the design has two explicit outer modes:

- `outer-execveat` retains the current anonymous memfd/no-executable-path
  contract and is used only when path semantics are proven irrelevant; and
- `outer-path-preserving` stages the verified payload and required closure in
  a private runtime root and launches through the original path semantics.

The runner chooses the mode only from a reviewed per-sample policy. It never
silently drops path-sensitive samples. Unknown dynamic metadata is preserved
for outer execution; HostContext continues to reject semantics it cannot
define.

### Full nightly execution

The nightly job is sharded by declared runtime and deterministic project ID,
not sampled. Shards process all 78 glibc, all 21 musl, and the one bionic
identity exactly once. A merge job verifies the union is exactly 100 IDs and
checks every baseline and outer result. A missing shard, closure, result, or
raw-input cleanup marker fails the job.

Function protection is independent: only entries in
`protection-policy.json` are transformed. No selector means no transform
attempt and an explicit `not-applicable` protection record.

## 4. Function inventory and selection

The parser adds a normalized `ElfFunctionSymbol` record with:

- table source (`.symtab` or `.dynsym`), table/index identity;
- exact name, binding, visibility, type, section index, value, and size;
- file/virtual range and containing executable load segment;
- alias/duplicate relationships and boundary confidence.

`.symtab` uses its linked string table and section metadata; `.dynsym` keeps
the existing dynamic-table path. Both are filtered to `STT_FUNC`, non-zero
size, checked arithmetic, one executable load segment, and AArch64 instruction
alignment. A merged inventory preserves both source identities.

Selectors are exact names by default. A unique name resolves directly; a name
with multiple valid identities fails with a diagnostic listing table, index,
address, and size. An explicit address/table-index selector can disambiguate.
Missing, zero-sized, overlapping, out-of-range, and aliased-without-safe-range
selections fail before any transform begins.

## 5. AsmStone-backed IR, CFG, and machine state

The adapter converts AsmStone decode results into project records that retain:

- original encoding/address and source instruction name;
- all explicit and implicit semantic operands with direction;
- GPR width/view, SP versus ZR role, SIMD/vector class, and register
  constraints;
- memory base/index/writeback/ordering/access-size information;
- direct targets, PC-relative reference kind, call/return/conditional/indirect
  control-flow class;
- NZCV/system/FP/vector side effects and unsupported-feature diagnostics; and
- an encoder provenance token sufficient for decode/encode/decode tests.

AsmStone's encoder is exposed only through a project `IAarch64InstructionCodec`
interface. Every rewritten instruction must pass round-trip encoding and
constraint checks. Unsupported or incomplete semantics are hard barriers for a
selected function, not instructions to rewrite heuristically.

CFG construction starts at the selected symbol entry, follows direct and
conditional targets inside the symbol range, and adds fallthrough edges. Calls
are modeled as call edges with ABI clobbers; returns terminate blocks. Indirect
branches, jump tables, embedded data, exception edges, and unresolved targets
make the selected function ineligible unless a dedicated recognizer proves
them. Unselected functions are not analyzed for transformation.

The machine-state layer models GPR aliases (`Wn`/`Xn`), SP/ZR encoding roles,
LR, NZCV, SIMD/vector classes, stack alignment/slots, call-clobber/preserve
sets, memory effects, and fixed platform registers. It produces pressure and
interference data for the original CFG and every generated block.

## 6. Transformation and register resources

### Pass contract

The protection request contains zero or more explicit pass names:

- `control-flow-flattening`
- `register-permutation`

No pass name means no transformation. If both are requested, the fixed order is
flattening first, permutation second. Each pass consumes/produces the project
IR and a resource plan; the composition is atomic.

### Control-flow flattening

For an eligible CFG, original basic blocks become protected blocks controlled by
a dispatcher state. Entry, normal exits, calls, returns, and preserved ABI
boundaries are explicit IR nodes. The state lives in a planned register or
spill slot, and dispatcher/edge code is included in the next pressure pass.
Direct targets and generated branches are resolved by the layout planner.
Functions with unresolved indirect control flow, unsupported state effects,
or unsafe exception/unwind obligations fail selection.

### Register permutation

Permutation operates on logical register values and instruction operands, not
on raw register-number text. It uses compatible register banks/views only and
preserves ABI-visible entry/exit and call boundaries through parallel-move
shuffles. Copy cycles are resolved with a planned scratch or spill slot.

The resource planner reserves fixed registers, dispatcher state, veneer
scratch, call-clobbered boundaries, stack alignment, and unwind requirements.
It builds an interference/resource graph and either assigns legal physical
registers or creates a verified spill slot. If neither is safe, the selected
function fails with a structured resource diagnostic and the operation publishes
nothing. No last-minute arbitrary scratch register is chosen.

## 7. ELF rewrite and validation

The writer starts from the original bytes and preserves every untouched range.
For the initial protection profile it supports sectioned, symbol-bounded
functions and a program-header layout with a legal executable placement for
generated code. It can append a protected code region, update the necessary
program/section metadata, patch the selected entry/trampoline, and repair
symbols/relocations owned by transformed code. Unsupported layout or unwind
requirements fail the selected operation rather than causing a best-effort
rewrite.

Branch-range checks select direct branches, veneers, or a function-level
placement failure. PC-relative `ADR`/`ADRP`/literal references are represented
as typed references and re-encoded after final layout. External relocations and
unselected bytes remain owned by the original ELF and are not rewritten without
an explicit rule.

Publication is transactional: write a temporary output, parse and validate it,
re-decode every transformed function, verify selected/unselected byte/range
invariants, then run the requested output identity checks before rename. Any
failure deletes the temporary output.

## 8. Reporting and compatibility evidence

The protect report includes request passes, exact selectors, resolved symbol
identities, per-function eligibility, CFG/IR coverage, register pressure and
spill decisions, pass results, output hashes, and publication status. A failed
selection includes a stable diagnostic code and no output path.

Real-sample evidence keeps static, baseline, outer, and HostContext layers
separate and adds protection policy/result data. Aggregate reports expose
validation count, baseline count, outer count, function-selector count,
transformation count, protected-equivalence count, and first-failure layers.

## 9. Rollback and compatibility strategy

The first implementation is guarded by the new `protect` command and explicit
outer profile/policy fields. Existing `validate`, no-op copy, legacy wrapper
evidence, and HostContext tests remain available while their report vocabulary
is migrated. A failed new E2E lane blocks promotion but does not alter the
legacy artifact path. The runtime closure lock, per-function report, and
schema-versioned evidence provide rollback/audit points without retaining raw
inputs.
