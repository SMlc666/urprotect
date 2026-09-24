# Public AArch64 real-sample corpus

This directory describes the public real-sample compatibility corpus. It does
not contain executable samples. The registry and candidate ledger contain only
provenance, hashes, expected ELF facts, selection rationale, and execution
policy.

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

The command is intentionally a CI-only command. It downloads each locked
artifact into `RUNNER_TEMP`, verifies its SHA-256, extracts it into a private
temporary directory, records static evidence, and removes the temporary tree
on exit. Raw archives and binaries are never copied into the repository or
uploaded as artifacts.

## Corpus rule

The selected registry contains exactly 20 distinct upstream project
identities. A libc, distribution, or build variant is a nested attribute of
one project and does not add to the count. The current selection is listed in
`selection.md`; `candidates.json` retains additional public candidates and
the reason they were selected, rejected, or deferred.

The selection is deliberately cross-ecosystem:

- common GNU/Linux programs: Bash, coreutils, curl, Git, OpenSSL, Perl,
  SQLite, Vim, Nano, and Caddy;
- compact and alternate producers: BusyBox, jq, ripgrep, and CMake;
- larger dependency/loader shapes: FFmpeg, Nginx, Node.js, PostgreSQL, and
  Redis;
- one Termux/bionic artifact and one musl rootfs artifact as runtime facts.

The final support claim still belongs to the ELF/HostContext contract. A real
sample observation does not promote a feature automatically.

## CI execution and evidence

Every pull request runs all 20 projects. Scheduled and release runs reuse the
same registry and runner and may add repeatability or release evidence. A
sample that is not applicable to a layer receives an explicit
`not-applicable` result; it is not silently omitted.

The runner records these layers:

1. static ELF fingerprint and UrProtect JSON validation;
2. baseline execution when the registry policy supplies a complete runtime
   closure and an isolation mode;
3. outer-wrapper behavior when a reviewed profile policy enables it;
4. HostContext behavior only for an image with the declared `urp_entry`
   contract.

Result vocabulary is fixed:

```text
accepted-and-runs
expected-rejected
unexpected-rejection
unexpected-acceptance
runtime-failure
environment-unavailable
not-applicable
```

The evidence root is `.artifacts/real-samples/<tier>/`. It contains normalized
fingerprints, readelf output, reports, hashes, environment facts, result JSON,
logs, and an aggregate report. It does not contain source archives, ELF
executables, shared objects, or runtime rootfs contents.

The post-run gate checks all 20 project directories, all four layers, registry
expectations, aggregate project IDs, non-empty evidence, and the absence of
raw binary-like files. A missing runtime or isolation capability is recorded
as `environment-unavailable` and fails the required CI job; it is not relabeled
as a compatibility pass.

## CI-first compatibility workflow

When a later compatibility task changes the parser, validator, packer,
launcher, native runtime, fixture contract, or compatibility docs, its PRD
must include a real-sample impact table:

| Field | Required value |
| --- | --- |
| Project IDs | every affected sample, not a guessed subset |
| Feature | the ELF fingerprint or contract feature under review |
| Layer | parser, outer wrapper, HostContext, or runtime fact |
| Oracle | static, baseline, outer, or HostContext observation |
| Expected result | exact registry result and failure boundary |
| Evidence | per-sample and aggregate artifact paths |

An unexpected rejection or acceptance keeps that compatibility task open until
it is classified. A new support claim requires a real observation, a
controlled positive fixture, a nearest-negative fixture, stable diagnostics,
an appropriate oracle, and updated contract/documentation evidence.
