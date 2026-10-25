# Indirect-control target-resolution and address-map report

**Task:** `.trellis/tasks/10-06-indirect-control-jump-tables`

**Report scope:** the remaining PRD acceptance item around `prd.md:57`: name the target-resolution modes and address-map bindings for every currently manifest-validated indirect-control row.

**Status source:** `fixtures/manifest.json` is the registry classification source. This report does not alter it or the PRD checkbox.

All addresses and ranges below are **ELF/layout virtual addresses and file offsets**. They are not ASLR runtime pointers. Ranges are given as start plus size (half-open range semantics). `FileOffset` and `VirtualAddress` are shown separately even where their numeric values happen to be equal.

## Promoted manifest rows

The manifest currently classifies exactly these two indirect-control rows as `validated`; both are native AArch64/glibc rows and both cover the signed-relative-32 jump-table family only.

| Manifest feature ID / registry status | Evidence unit ID and exact root | Current checker results | Semantic target modes | Table ownership / placement policy | Behavior witness |
|---|---|---|---|---|---|
| `runtime.indirect-control.jump-table.glibc.host-context-entry` — `validated` | Unit `runtime.indirect-control.jump-table.glibc.host-context-entry`; fresh local root `.artifacts/indirect-control/ordinary-musl-va-overlap-repair-glibc-final-20261022T045325Z-3105/` (unit directory is `<root>/runtime.indirect-control.jump-table.glibc.host-context-entry/`). | Indirect-control evidence checker: **PASS**; rehydration evidence checker: **PASS**. Both exact commands and output are recorded below. | Indirect branch: **`BoundedSet`**. Each of four table-entry targets and the default target: **`Exact`** in the typed semantic table contract. Evidence label `bounded-relative-table` is descriptive JSON, not an enum value. | Layout evidence schema 3. Clone ownership ordinal `0` = `Ambiguous`; inventory incomplete. Permissions `4` = `PF_R`; rewrite policy `1` = `CopiedAndRetargeted`. | One in-function invocation walks indices `0,1,2,3`, observes exact results `[17, 103, -7, 91]`, and returns entry/process status `91` only after the ordered trace is accepted. The checker verifies source/transformed handoffs and streams and the four fail-closed negatives. |
| `runtime.indirect-control.shared-jump-table-copy.glibc.host-context-entry` — `validated` | Evidence unit ID is **different**: `runtime.indirect-control.shared-table.glibc.host-context-entry`; root `.artifacts/indirect-control/shared-copy/current/` (unit directory is `<root>/runtime.indirect-control.shared-table.glibc.host-context-entry/`). | Shared jump-table evidence checker: **PASS**; rehydration evidence checker: **PASS**. Both exact commands and output are recorded below. | Indirect branch: **`BoundedSet`**. Each of four table-entry targets and the default target: **`Exact`** in the typed semantic table contract. The shared behavior JSON does not itself carry a `targetResolutionMode` field. | Layout evidence schema 3. Clone ownership ordinal `2` = `Shared`; inventory incomplete. Permissions `4` = `PF_R`; rewrite policy `1` = `CopiedAndRetargeted`. Four section-linked owner references cover selected `urp_entry` and unselected `urp_observer` (two reference sites each); this is not a claim that the complete owner inventory is known. | Selected `urp_entry` reads the clone; source table bytes remain unchanged and the unselected observer still uses the original table. Selected entry and observer source/transformed statuses are `91`; the shared checker validates these facts. |

### Ordinary glibc row: six layout AddressMap rows

Source and output values below are copied from the current fresh root's `rehydration.json` → `layoutEvidence.addressMap`. The six rows comprise four mapped target blocks, the table, and the emitted code region.

| AddressMap identity | Source file offset / VA (size) | Output file offset / VA (size) |
|---|---|---|
| `0x2D8` (target block) | `0x2D8` / `0x2D8` (`0x4`) | `0x11198` / `0x20138` (`0x4`) |
| `0x2E0` (target block) | `0x2E0` / `0x2E0` (`0x4`) | `0x111A4` / `0x20144` (`0x4`) |
| `0x2E8` (target block) | `0x2E8` / `0x2E8` (`0x4`) | `0x111B0` / `0x20150` (`0x4`) |
| `0x2F0` (target block) | `0x2F0` / `0x2F0` (`0x4`) | `0x111BC` / `0x2015C` (`0x4`) |
| `0x330:4:0:3` (table) | `0x330` / `0x330` (`0x10`) | `0x12000` / `0x21000` (`0x10`) |
| `region:0000000001` (emitted region) | `0x2B0` / `0x2B0` (`0x7C`) | `0x11150` / `0x20090` (`0x11C`) |

Table identity `0x330:4:0:3` denotes the signed-relative-32 table with indices 0 through 3. Its source range is file offset/VA `0x330`, size `0x10`; its cloned output range is file offset `0x12000`, VA `0x21000`, size `0x10`. The source target base is VA `0x2D8`; the output target base is VA `0x20138`.

### Ordinary glibc row: four independent entry target/base bindings

These are the four planner-derived `layoutEvidence.jumpTableTargetBindings`. Each binds the source target and base to their mapped output target and base, independently of the six AddressMap range rows.

| Entry index | Source target VA → output target VA | Source target-base VA → output target-base VA | Source encoded value → output encoded value |
|---:|---|---|---:|
| 0 | `0x2D8` → `0x20138` | `0x2D8` → `0x20138` | `0` → `0` |
| 1 | `0x2E0` → `0x20144` | `0x2D8` → `0x20138` | `8` → `12` |
| 2 | `0x2E8` → `0x20150` | `0x2D8` → `0x20138` | `16` → `24` |
| 3 | `0x2F0` → `0x2015C` | `0x2D8` → `0x20138` | `24` → `36` |

The entries are signed 32-bit relative values (width 4, scale 1, addend 0). The behavior record names source symbols `urp_jump_table_case0` through `urp_jump_table_case3`, records indices `[0,1,2,3]`, exact results `[17,103,-7,91]`, and says `urp_entry` returns 91 only after its in-function ordered trace matches.

### Shared glibc row: six layout AddressMap rows

Source and output values are from the shared unit's `rehydration.json` → `layoutEvidence.addressMap`.

| AddressMap identity | Source file offset / VA (size) | Output file offset / VA (size) |
|---|---|---|
| `0x2B8` (target block) | `0x2B8` / `0x2B8` (`0x4`) | `0x11198` / `0x20138` (`0x4`) |
| `0x2C0` (target block) | `0x2C0` / `0x2C0` (`0x4`) | `0x111A4` / `0x20144` (`0x4`) |
| `0x2C8` (target block) | `0x2C8` / `0x2C8` (`0x4`) | `0x111B0` / `0x20150` (`0x4`) |
| `0x2D0` (target block) | `0x2D0` / `0x2D0` (`0x4`) | `0x111BC` / `0x2015C` (`0x4`) |
| `0x32C:4:0:3` (table) | `0x32C` / `0x32C` (`0x10`) | `0x12000` / `0x21000` (`0x10`) |
| `region:0000000001` (emitted region) | `0x290` / `0x290` (`0x7C`) | `0x11150` / `0x20090` (`0x11C`) |

Table identity `0x32C:4:0:3`: source file offset/VA `0x32C`, size `0x10`; output file offset `0x12000`, VA `0x21000`, size `0x10`. Source target base is VA `0x2B8`; output target base is VA `0x20138`.

### Shared glibc row: four independent entry target/base bindings

| Entry index | Source target VA → output target VA | Source target-base VA → output target-base VA | Source encoded value → output encoded value |
|---:|---|---|---:|
| 0 | `0x2B8` → `0x20138` | `0x2B8` → `0x20138` | `0` → `0` |
| 1 | `0x2C0` → `0x20144` | `0x2B8` → `0x20138` | `8` → `12` |
| 2 | `0x2C8` → `0x20150` | `0x2B8` → `0x20138` | `16` → `24` |
| 3 | `0x2D0` → `0x2015C` | `0x2B8` → `0x20138` | `24` → `36` |

These are signed 32-bit relative entries (width 4, scale 1, addend 0). The shared behavior witness records `selectedConsumerReadsClone=true`, `sourceTableUnchanged=true`, and `unselectedObserverUsesOriginalTable=true`; source and transformed observer statuses are both 91.

## Interpretation boundaries

- **Semantic resolution:** `SemanticTargetResolution` has exactly `Exact`, `BoundedSet`, `RuntimeResolved`, and `Unresolved`. `Aarch64SemanticPlanFactory.ApplyResolvedJumpTableTarget` assigns the indirect branch a `BoundedSet`; `AddJumpTableExtensions` makes each table entry target and the default target `Exact` (`src/UrProtect.Core/SemanticPlanning/SemanticValueModels.cs:7-13`; `Aarch64SemanticPlanFactory.cs:1263-1290,1517-1593`). A bounded branch remains a finite candidate set; the per-entry exact bindings do not turn the branch mode into one `Exact` target.
- **Evidence labels are not enum fields:** the ordinary behavior JSON's `targetResolutionMode: "bounded-relative-table"` is a checker/report label. It is not the source enum spelling `BoundedSet`. The shared behavior JSON contains no `targetResolutionMode` field. The enum interpretation above is sourced from the typed semantic enum/factory, not inferred from those labels.
- **Ownership is separate:** the clone's ownership classification (`Ambiguous` or `Shared`) describes source-table ownership confidence, not target-resolution mode. In both rows `ownerInventoryComplete=false`. The ordinary clone's empty owner-reference list does not prove it is private; it remains `Ambiguous`. The shared row records selected and observer owner references but still marks its inventory incomplete.
- **Fixup resolution is separate:** fixup state is `Resolved`, `Deferred`, or `Unresolved` (`src/UrProtect.Core/SemanticPlanning/SemanticPlanSnapshotContracts.cs:12-18`); `Deferred` is not a fifth semantic target mode. Neither checker result, clone ownership, rewrite policy, nor successful output mapping substitutes for a semantic resolution mode or a fixup-state assertion.
- **Layout bindings are separate:** `AddressMap` ranges and `jumpTableTargetBindings` describe source-to-output placements and entry re-encoding. They do not independently determine source ownership or semantic target resolution. The typed map retains both file and virtual address domains (`src/UrProtect.Core/SemanticPlanning/AddressMap.cs:7-32`; layout target-binding contract in `src/UrProtect.Core/ElfLayout/ElfLayoutContracts.cs`).
- **Registry and local evidence caveat:** the manifest-listed historical ordinary evidence path is `.artifacts/indirect-control/pr/runtime.indirect-control.jump-table.glibc.host-context-entry`. The current checker was run against `.artifacts/indirect-control/pr` and rejects it with `jump-table behavior identity is invalid` (exit 1); that old unit has schema-1 layout evidence with only a region mapping and no current clone mapping. Do not say that historical root passed. The exact fresh ordinary root listed in the audit, `.artifacts/indirect-control/ordinary-musl-va-overlap-repair-glibc-final-20261022T045325Z-3105/`, passes both current exact-root checkers. It is a fresh local, unregistered root—not official CI promotion or a replacement registry path. `fixtures/manifest.json` remains the source of the row's `validated` registry classification; this report leaves runtime/registry status unchanged while documenting that the manifest path cannot currently be revalidated locally.

## Separate non-promoted observations and open rows

These are not additional promoted manifest indirect-control rows and must not be folded into the two-row table above.

- **External provider — unknown:** `runtime.indirect-control.external-provider.glibc.host-context-entry` remains `unknown` in `fixtures/manifest.json` and its evidence is scoped/non-promoted. Its consumer import/dispatch can be described as `RuntimeResolved`, but provider table and target addresses are in the separately pinned provider identity domain. No in-image jump-table mapping is asserted or invented here.
- **Ordinary musl — scoped observation only:** the audit records a hosted exact-root ordinary signed-relative-32 observation (run `39864478180`). It is not a promoted manifest indirect-control row and does not change runtime support status.
- **Shared musl — pending/unknown:** `runtime.indirect-control.shared-table.musl.host-context-entry` has no current positive runtime root/result recorded in the audit.
- **Ordinary and shared Bionic — pending/unknown:** `runtime.indirect-control.jump-table.bionic.host-context-entry` and `runtime.indirect-control.shared-table.bionic.host-context-entry` remain open. Regression/CI matrix `expected: "pass"` entries are configuration expectations, not completed-run evidence; the audit records no current positive Bionic table root and notes the prior hosted failure. No Bionic runtime claim is made.
- **Static local callback — scoped row, not a promoted manifest indirect-control row:** its bounded target mode is `Exact`, with the callback preserved at source VA `0x1E0` and mapped to the same output VA. This is an identity-preserved function-pointer target, not a table map or general indirect-call promotion.
- **Runtime GLOB_DAT `getpid` import — scoped row, not a promoted manifest indirect-control row:** its call target mode is `RuntimeResolved`. The owner is the tested non-PLT GLOB_DAT import/GOT slot (VA `0x1FFF8`, file offset `0xFFF8`); this is not jump-table storage and does not add a table AddressMap row.

## Contracts and checker/source references

- Semantic mode enum and typed table factory: `src/UrProtect.Core/SemanticPlanning/SemanticValueModels.cs:7-13`, `src/UrProtect.Core/SemanticPlanning/Aarch64SemanticPlanFactory.cs:1263-1290,1517-1593`.
- Typed address ranges: `src/UrProtect.Core/SemanticPlanning/AddressMap.cs:7-32`; planner-derived per-entry output target/base bindings: `src/UrProtect.Core/ElfLayout/ElfLayoutContracts.cs` (`ElfLayoutJumpTableTargetBinding`). Layout evidence schema-v3 clone ownership, permission and rewrite values are distinct from the semantic snapshot ownership enum.
- Independent evidence checkers: `scripts/check-indirect-control-evidence.py`, `scripts/check-shared-jump-table-evidence.py`, and `scripts/check-rehydration-evidence.py`.
- Registry classifications and declared evidence references: `fixtures/manifest.json`, feature IDs above.
- This is a **task report**, not an existing CLI JSON projection. The current CLI command/product/rehydration reports do not expose this cross-row target-mode and AddressMap summary; no claim is made that these tables are emitted by a product CLI.

## Read-only validation performed for this report

The following exact-root evidence checks were run with ambient `PYTHONPATH` unset. Four passed; the one failure is the manifest-listed stale ordinary local root described above. No hosted CI was run.

```sh
env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 python3 scripts/check-indirect-control-evidence.py .artifacts/indirect-control/ordinary-musl-va-overlap-repair-glibc-final-20261022T045325Z-3105 --tier pr --runtime glibc --require-runtime-identity --unit runtime.indirect-control.jump-table.glibc.host-context-entry
# PASS: all table cases, measured handoff/streams, and four fail-closed negatives

env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 python3 scripts/check-rehydration-evidence.py .artifacts/indirect-control/ordinary-musl-va-overlap-repair-glibc-final-20261022T045325Z-3105/runtime.indirect-control.jump-table.glibc.host-context-entry --tier pr --runtime glibc --require-runtime-identity --unit runtime.indirect-control.jump-table.glibc.host-context-entry
# PASS rehydration evidence

env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 python3 scripts/check-shared-jump-table-evidence.py .artifacts/indirect-control/shared-copy/current/runtime.indirect-control.shared-table.glibc.host-context-entry --runtime glibc --unit runtime.indirect-control.shared-table.glibc.host-context-entry --selected-function dynsym:2
# PASS: selected consumer loads the read-only clone; observer and source table remain unchanged

env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 python3 scripts/check-rehydration-evidence.py .artifacts/indirect-control/shared-copy/current/runtime.indirect-control.shared-table.glibc.host-context-entry --tier pr --runtime glibc --unit runtime.indirect-control.shared-table.glibc.host-context-entry
# PASS rehydration evidence

env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 python3 scripts/check-indirect-control-evidence.py .artifacts/indirect-control/pr --tier pr --runtime glibc --unit runtime.indirect-control.jump-table.glibc.host-context-entry
# EXPECTED STALE-ROOT FAILURE (exit 1): jump-table behavior identity is invalid
```

**Report artifact:** `.trellis/tasks/10-06-indirect-control-jump-tables/research/indirect-control-target-resolution-report.md`.

No automated test was added for this manually assembled report. No source, product, spec, fixture-manifest, or runtime-status changes were made. The report does not alter runtime/registry status. Hosted CI was not run; no files were staged, committed, pushed, or merged.