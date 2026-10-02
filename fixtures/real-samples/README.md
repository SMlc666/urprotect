# Public AArch64 real-sample corpus

This directory describes the public real-sample compatibility corpus. It does
not contain executable samples. The registry and candidate ledger contain only
provenance, hashes, expected ELF facts, selection rationale, and execution
policy.

## Locked registry

The selected registry contains exactly **100 distinct upstream project
identities**. The approved target is 100 and the shortfall is zero. A libc,
distribution, package, build, or version variant is a nested attribute of one
project and never adds to the count. `selection.md` lists every selected
identity and the reviewed source/runtime mix.

The reviewed increment is 23 promoted Debian deferred candidates, 37 new
Debian Bookworm AArch64 projects, and 20 new Alpine v3.22 AArch64 APK
projects. The resulting runtime mix is 78 glibc, 21 musl, and 1 bionic
identity. The Alpine APK increment alone contributes 20 distinct musl
projects.

The Debian package-index SHA-256 is
`2ddb1737692e8c45c53e8d57c0ce4cd21c78c5703b830c3226b1423566a06c00`; the
Alpine APKINDEX SHA-256 is
`1f7a5be0ef6c857f2aa1013f2be0b678d2c5dd2ad3a4eee5760a184be58bbe20`.

`runtime-closures.json` is the execution policy for the complete registry. It
locks the Debian `Packages.xz` and Alpine `APKINDEX` inputs, resolver family,
loader identity, and the required `accepted-and-runs` baseline/outer layers.
The runner resolves only the locked transitive Debian `Depends` and Alpine
providers into a temporary rootfs; it never uses ambient host libraries. The
bionic identity is executed through the locked native ARM64 Termux container
and `/system/bin/linker64`.

## Local boundary

Local commands are metadata-only:

```sh
python3 scripts/validate-real-samples.py \
  fixtures/real-samples/manifest.json \
  --candidates fixtures/real-samples/candidates.json
python3 tests/test_real_sample_manifest.py
```

They do not download, extract, or launch a real sample. The execution entry
point requires both the GitHub Actions environment and a native AArch64 runner:

```sh
./scripts/run-real-sample-matrix.sh --tier pr
```

The command is intentionally CI-only. It downloads each locked artifact into
`RUNNER_TEMP`, verifies its SHA-256, extracts it into a private temporary
directory, records static evidence, and removes the temporary tree on exit.
Raw archives and binaries are never copied into the repository or uploaded.

## CI execution and evidence

Every pull request runs all 100 approved projects. Scheduled and release runs
reuse the exact registry and runner and may add repeatability or release
evidence, never a subset. A sample that is not applicable to a layer receives
an explicit `not-applicable` result; it is not silently omitted.

The runner records these layers. Static success is `validated`: it proves
bounded fingerprinting and UrProtect validation only, and never claims that the
sample process ran.

1. static ELF fingerprint and UrProtect JSON validation;
2. baseline execution in the runtime closure declared by
   `runtime-closures.json`;
3. outer-wrapper behavior in the same closure through the profile-matched
   native launcher;
4. HostContext behavior only for an image with the declared `urp_entry`
   contract.

Result vocabulary is fixed:

```text
validated
accepted-and-runs
expected-rejected
unexpected-rejection
unexpected-acceptance
runtime-failure
environment-unavailable
not-applicable
```

The evidence root is `.artifacts/real-samples/<tier>/`. It contains normalized
fingerprints, bounded readelf output, reports, hashes, environment facts,
result JSON, logs, and an aggregate report. It does not contain source
archives, ELF executables, shared objects, or runtime rootfs contents.
Aggregate schema 2 reports include distinct-identity feature histograms,
producer/runtime/loader and page-size coverage, diagnostics, result
classifications, and the fixed first-failure taxonomy
(`acquisition`, `fingerprint`, `parse-model`, `static-validation`, `outer`,
`host-context`, `environment`).

A metadata-only baseline is retained at
`fixtures/real-samples/baseline-aggregate.json` and
`fixtures/real-samples/baseline-aggregate.md`. It is generated without network
or ELF acquisition:

```sh
python3 scripts/render-real-sample-report.py \
  fixtures/real-samples/manifest.json --tier pr --registry-only \
  --artifact-root fixtures/real-samples \
  --output-json fixtures/real-samples/baseline-aggregate.json \
  --output-markdown fixtures/real-samples/baseline-aggregate.md
```

Baseline fields are labelled registry metadata; only the CI aggregate produced
from acquired, hash-verified samples is an observation report. Features at or
above the 5% distinct-identity threshold carry an explicit roadmap disposition
in `feature-dispositions.json`; this record does not promote product support.

The post-run gate checks all 100 project directories, all four layers, the
runtime-closure expectations, aggregate project IDs, non-empty evidence,
cleanup markers, and the absence of raw binary-like files. A missing runtime
or isolation capability is recorded as `environment-unavailable` and fails the
required CI job; it is not relabeled as a compatibility pass.

## CI-first compatibility workflow

When a later compatibility task changes the parser, validator, packer,
launcher, native runtime, fixture contract, or compatibility docs, its PRD
must include a real-sample impact table for every affected sample and layer.
A real observation never widens a product compatibility claim by itself. A new
support claim still requires controlled positive and nearest-negative fixtures,
stable diagnostics, an appropriate oracle, and synchronized contract and
documentation evidence.
