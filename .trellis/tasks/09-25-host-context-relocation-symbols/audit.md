# HostContext relocation and symbol support audit

## Real-sample selection evidence

- Downloaded native PR artifact `real-samples-pr-36220307292` from successful
  GitHub Actions run `36220307292`, commit `d815eecd2f029c2cd07d9e295aae91ee90935354`.
- The schema-2 aggregate contains 20 distinct project identities. Their
  fingerprints contain `DT_GNU_HASH` and PLT relocations in 20/20; symbol-
  version metadata is present in 19/20 (all except BusyBox). This informed
  selection only; it does not promote normal sample executables to HostContext
  entry images.
- Every sample retained its existing `static: accepted-and-runs` classification
  and `hostContext: not-applicable`; no public sample declares the HostContext
  `urp_entry` ABI.

## Accepted contracts

### Weak undefined JUMP_SLOT

The validated row is only `runtime.host-context.weak-undefined-jump-slot`:
one complete NOW-bound RELA PLT tuple, JUMP_SLOT records with nonzero symbol
indices, file-backed weak undefined `STT_FUNC` records with exact
`st_other == STV_DEFAULT`,
aligned writable targets, no dependencies/version tags/`DT_SYMBOLIC`, and the
ordinary native global lookup scope. The managed native AArch64 glibc entry
observes the unresolved weak function address as zero and returns 53.
`R_AARCH64_JUMP_SLOT` in regular `DT_RELA` is explicitly rejected; it cannot
bypass the PLT-specific rule. Existing RELATIVE/RELR and GLOB_DAT status-29
semantics are unchanged.

`host_context_plt_self_test.c` covers strong binding, non-function type,
non-default visibility, defined symbols, wrong relocation type, ordinary
DT_RELA JUMP_SLOT, extra `st_other` flags, unaligned/read-only/unmapped
targets, dependencies, version tags, partial/wrong PLTREL tuples, missing NOW,
duplicate tags, and `DT_SYMBOLIC`. Every negative `load_image` returns its
stable status and clears the sentinel handle to zero before loader handoff.

### Import-side symbol versions

The prior generic `runtime.host-context.symbol-version` rejection description
did not match the existing libc dependency fixture, which already carried
`DT_VERSYM`/`DT_VERNEED` and successfully dispatched. The contract now
separates import requirements from versioned exports/entry selection.

`runtime.host-context.dependency-symbol-version-requirements` accepts only
`DT_NEEDED libc.so.6`, `DT_GNU_HASH`, and complete
`DT_VERSYM`/`DT_VERNEED`/`DT_VERNEEDNUM`.
Preflight requires GNU hash, bounds the file-backed VERSYM range using the
checked GNU dynamic symbol count, and rejects SysV `DT_HASH` combinations. It
validates version-need and auxiliary records, chain counts,
monotonicity, string offsets, exact `vn_file == libc.so.6`, version-name ELF
hashes, unflagged version requirements, and version indices >= 2 with the
reserved high bit clear. `RTLD_NOW` delegates matching to the native glibc
loader. The managed dependency entry returns status 37. `DT_VERDEF`/`NUM`,
versioned entry selection, weak-version requirements, and versioned imports
for musl/bionic SONAMEs remain rejected. No musl or bionic version-resolution
claim follows.

`host_context_version_self_test.c` positively loads the versioned dependency
fixture and negatively checks an empty/mismatched `vn_file`, an out-of-scope
SONAME, SysV hash metadata and `DT_SYMBOLIC`, unmapped GNU hash/VERSYM/Verneed/
auxiliary pointers, over-cap hash counts, a chain terminator cleared at the
last mapped word, a mapped-but-short VERSYM range, bad version hashes/indices,
weak-version flags, bad `vn_next`/`vna_next` links and declared counts,
incomplete tuples, missing VERSYM, and versioned definitions.
Every rejection retains `URP_STATUS_UNSUPPORTED` or `URP_STATUS_LOAD_FAILED`
with a zero handle before loader handoff.

## Cross-layer ownership

- The managed parser already models `R_AARCH64_JUMP_SLOT` as a typed relocation
  kind and `VersionNeed` records/auxiliaries; parser tests now explicitly
  assert both boundaries.
- `host_image_validation.c` is the sole native owner of relocation, symbol,
  GNU-hash, and accepted Verneed preflight. `host_adapter.c` retains
  memfd sealing, `RTLD_NOW`, symbol lookup, and release ownership.
- No frame, HostContext ABI, capability, or report wire layout changed.
- Manifest rows separate parser observation, exact PLT support, libc import
  version resolution, and rejected versioned definitions/entry lookup.

## Local verification

- `dotnet test UrProtect.sln --configuration Release --no-restore`: PASS,
  136/136 managed tests.
- `make -C native/urprotect-runtime -B test`: PASS for baseline runtime,
  weak JUMP_SLOT, and libc symbol-version preflight self-tests.
- `make -C native/urprotect-runtime contract-check`: PASS; ABI/frame sizes
  unchanged.
- `native/urprotect-runtime/test_managed_host_context.sh`: PASS; retains
  `dependency-version-metadata.txt`, `version-self-test.log`,
  `dependency-result.txt` (status 37), `plt-self-test.log`, and
  `plt-result.txt` (status 53) under `.artifacts/host-context/managed/`.
- `scripts/validate-fixtures.py ... --tier pr`, tier PR evidence gate, and
  feature evidence gates for the new rows and both rejected boundaries: PASS.
- `tests/test_fixture_matrix.py`: PASS, 24/24; regression matrix tests: PASS,
  5/5, with all 14 mapped regression cases validated.
- Real-sample manifest, fingerprint, evidence, security, and aggregate tests:
  PASS; 20-project metadata validates.
- `scripts/run-coverage-fuzz.sh --tier pr`: PASS.
- `scripts/run-regression-stress.sh --tier pr`: PASS, six categories.

## Remaining gate

The initial feature-branch run on `17ce404` (`36230780225`, PR; and
`36230777141`, push) failed the HostContext evidence step because the managed
script stopped in `version-self-test`; the expected downstream TLS artifact was
therefore absent. Its retained log showed the failing Make target but no
self-test diagnostic. Later runs exposed two independent issues: the GNU-hash
chain negative-test setup assumed a linker-specific gap, and GNU ld on the
Ubuntu 24.04 AArch64 runner emits both `DT_HASH` and `DT_GNU_HASH` by default.
The validated import-version slice intentionally rejects SysV and combined
hash metadata; the positive fixture now explicitly links with
`--hash-style=gnu`, retaining the combined-hash mutation as a negative test.
The setup now finds a mapped GNU-hash chain boundary across file-backed
`PT_LOAD` ranges. HostContext CI pipelines use `set -o pipefail`; failed
positive preflight checks emit test-only stage diagnostics, and CI retains the
controlled fixture plus full readelf output. The GCC warning in the runtime
self-test's ELF-offset locals was fixed by initializing them before bounded
helper assignment. Local native runtime and managed HostContext tests pass;
this commit's CI must confirm the native AArch64 artifact and evidence gates.
Only retained native AArch64 glibc artifacts satisfy the runtime evidence
contract; local evidence is supplemental. The parent task remains active until
all remaining child tasks, release integration, and the PR workflow are
complete.
