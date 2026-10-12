# TLS matrix completion evidence

## Current producer result

The checked-in PR producer is:

- `scripts/run-tls-prerequisite-probes.py`
- `scripts/check-tls-prerequisite-evidence.py`
- `scripts/run-tls-runtime-matrix.py`
- `scripts/check-tls-runtime-matrix-evidence.py`

The PR artifact roots are `.artifacts/tls-prerequisites/pr` and
`.artifacts/tls-runtime/pr`. Both have closed `SHA256SUMS` manifests and pass
their dedicated checkers.

The prerequisite producer retains eight independent Android packed-relocation
tag rows. Each row records the canonical tag value, managed HostContext policy
rejection, native `urp_host_image_validate` status `URP_STATUS_UNSUPPORTED`,
zero publication/handle state, and source hash. The PT_TLS parity projection
retains baseline, executable, read-only owner, empty-memory, filesz/memsz, and
non-power-of-two alignment mutations. StructuralElf observation and the stricter
HostContext handoff predicate are explicitly separate.

The transformed matrix retains exactly 60 rows:

```text
five models x two profiles x three runtimes x two lifecycle boundaries
```

Every row retains source bytes/hash, PT_TLS template/hash/file-size/memory-size/
zero-fill/alignment/owner, managed semantic-gate output, native common-source
preflight JSON, result, reason, loader/toolchain identity, first failure,
publication, rollback, and lifecycle observations. The only
`accepted-and-runs` row is:

```text
initial-exec x host-context-entry x glibc x current-thread
```

That row independently copies the managed Protected Image, Native Image, TLS
template, and native handoff control artifacts from the transformed AArch64
glibc lane. All other rows remain independent `not-applicable` or
`environment-unavailable` evidence and cannot inherit the glibc hashes.

## Runtime boundaries

The local environment has native AArch64 GNU tooling but no `musl-gcc` and no
Docker/Podman. CI retains the pinned musl and Termux/bionic covering lanes.
Their absence locally is represented row-locally and never promoted. The
existing six-cell `fixtures/runtime-matrix.json` remains loader/environment
coverage and is not used as transformed TLS support evidence.

The bionic sectionless image decision remains loader-specific: the common
transformed contract uses sectioned images; StructuralElf observation and the
glibc sectionless oracle do not promote bionic sectionless support.
