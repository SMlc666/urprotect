# Technical Design

## 1. Product Shape

The first product is a thin, installable boundary over the existing
`UrProtect.Core` infrastructure:

```text
urprotect CLI
    -> command/options and exit-code mapper
    -> validation/report orchestration
    -> UrProtect.Core parser, LoadMap, metadata, AsmStone analysis
    -> atomic no-op writer and hash proof
    -> human or JSON report
```

The product does not add a writer that serializes `ElfFile`. The only artifact
writer remains a byte copy of the original input.

## 2. CLI and Exit-Code Boundary

The CLI owns argument parsing, output streams, exit codes, and process-level
exception handling. Core owns validation and structured diagnostics.

Proposed command contract:

```text
urprotect validate <input>
  [--copy <output>]
  [--json <path|->]
  [--no-analysis]
```

Rules:

- `--json -` reserves stdout for one JSON document; human progress/errors use
  stderr.
- A file path report is written to a temporary sibling, flushed, and atomically
  renamed only after the report is complete.
- `--copy` and report publication are independent outputs but share one
  validation result. A failed validation publishes neither.
- A requested copy identity failure maps to exit code 5; parser/validator
  errors map to 4; input/output filesystem failures map to 3.
- Unexpected exceptions are caught only at the CLI boundary, logged as a stable
  internal diagnostic with a correlation id, and return 10.

The current `NoOpValidationResult` remains the internal source of truth. A
product report projection converts it once; fixture scripts do not reimplement
the report model.

## 3. Report Schema v1

The report projection is a product-owned DTO/serializer layer outside the core
parser. It emits deterministic property order and array order. Suggested shape:

```json
{
  "schemaVersion": 1,
  "toolVersion": "0.1.0",
  "input": { "byteLength": 123, "sha256": "..." },
  "elf": {
    "class": "ELF64",
    "endianness": "little",
    "machine": "AArch64",
    "type": "ET_DYN",
    "kind": "PieExecutable"
  },
  "dynamic": {
    "neededLibraries": [],
    "soname": "libfixture.so",
    "rpath": "/lib",
    "runPath": "/lib"
  },
  "summary": {
    "programHeaders": 11,
    "loadSegments": 4,
    "dynamicEntries": 31,
    "dynamicSymbols": 42,
    "relocations": { "rela": 12, "relr": 3, "androidPacked": 0 },
    "analysisCandidates": 8
  },
  "diagnostics": [],
  "output": {
    "requested": true,
    "byteIdentical": true,
    "sha256": "..."
  }
}
```

The exact schema is finalized before implementation and captured in a checked-
in JSON example/golden test. Sensitive or machine-specific absolute paths are
omitted unless an explicit future option requests them.

## 4. Validation Flow

```text
parse CLI options
  -> read input and compute source hash
  -> NoOpPipeline.Validate(...)
  -> project core result to ReportV1
  -> optionally ValidateAndCopy / verify output hash
  -> optionally publish report atomically
  -> select documented exit code
```

The copy path must remain source-preserving and destination-local. Report
generation must not change the validation result or cause a second parse with
different behavior.

## 5. Release Packaging

Use two explicit publish profiles:

- `linux-arm64-glibc`: self-contained native ARM64 bundle for the GitHub-hosted
  ARM64 glibc runner;
- `linux-musl-arm64`: self-contained native ARM64 bundle validated in the
  pinned musl container.

The SDK/RID setup must be made compatible with locked restore before packaging.
Each package contains:

- the `urprotect` executable;
- a short README and supported-boundary notice;
- `THIRD_PARTY_NOTICES` and AsmStone/LLVM/AARCHMRS provenance;
- version/checksum metadata.

The release workflow also grants `contents: write` only to the release package
job so a published release can receive its archives through `gh release
upload`; ordinary CI retains read-only repository permissions. Release tags
are passed through environment variables rather than interpolated into shell
commands.

Release jobs build from a clean checkout, record `global.json`, AsmStone commit,
fixture manifest hash, runner/environment manifest, and package checksums.
Build outputs are artifacts, never dependency caches.

## 6. Test Boundaries

### CLI unit/integration

- option parser and exit-code matrix;
- report projection and deterministic JSON serialization;
- invalid input, missing path, permission, conflicting output, and report
  publication failures;
- copy and report atomicity;
- SHA-256 and byte identity.

### Product fixture E2E

Reuse the manifest runner as the behavior oracle, but invoke the packaged CLI
where possible. Keep compiler/toolchain builders outside the product runtime.
The release gate must run native glibc and the pinned musl container smoke;
Android remains its separate APK/JNI job.

### Golden compatibility

Store small checked-in expected JSON reports for the synthetic ELF fixture,
minimal valid PIE, stripped fixture, and one representative real toolchain
fixture. Golden tests compare schema and stable fields, not ASLR-sensitive
addresses or environment paths.

## 7. Compatibility and Rollback

- Report schema changes require a new schema version or an explicit compatible
  additive-change review.
- Exit-code changes are breaking product changes and require release notes.
- If packaging fails on a RID or runtime dependency, do not weaken the input
  boundary; fix the publish profile or defer that package with visible evidence.
- A release candidate can be rolled back by retaining the previous archive and
  tag; no source ELF is ever modified by the product.

## 8. Security and Supply Chain

Inputs are hostile. Report serialization escapes strings and limits any raw
diagnostic output to bounded data. Release archives use pinned dependencies and
checksums. AsmStone remains the only instruction backend and its notices remain
included.
