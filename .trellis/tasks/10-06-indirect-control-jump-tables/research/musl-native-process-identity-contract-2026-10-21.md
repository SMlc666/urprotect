# Bounded native-process runtime identity contract (2026-10-21)

This contract is limited to the ordinary signed-relative-32 jump-table evidence
runner and its existing HostContext native handoff. It does not change the
HostContext public ABI, image format, provider configuration, semantic resolver,
publication, shared-table runner, or Bionic lane.

## Carrier and observations

The existing `host-context-handoff` JSON record gains an optional, explicitly
versioned `runtimeIdentity` object (`schemaVersion: 1`). The identity is emitted
by the C handoff process itself, not by the runner's Python/.NET runtime or a
container/CLI label. It is independently emitted for the source and transformed
image handoff. It binds the current process ID, role, SHA-256 of the exact input
image bytes read by that process, the helper executable, and the actual runtime
files mapped into that process.

Before dispatch, the helper reads bounded `/proc/self/maps` evidence, identifies
the mapped loader/libc by mapped path plus device/inode, opens each mapped file
without following a final symlink, verifies regular-file and device/inode identity,
then retains the exact bytes used for its file digest. The helper executable is
retained through `/proc/self/exe` and is independently parsed by the checker; its
`PT_INTERP` loader basename must match the loader observed in the process maps.
The raw maps observation and all retained files are closed-root artifacts with
relative, fixed names; no host path is serialized into the Protected Image,
Native Image, snapshot, or provider state.

For glibc, the mapped loader (`ld-linux-aarch64.so.1`) and libc (`libc.so.6`)
are distinct observations. For musl, the combined mapped `ld-musl-aarch64.so.1`
file is recorded as both loader and libc and the two retained byte identities
must agree. The runtime version is independently recomputed from retained
runtime bytes: musl uses its unique `Version X.Y.Z` marker in the combined
loader/libc file; glibc uses its unique `release version X.Y` marker in libc,
which the native helper cross-checks against `gnu_get_libc_version()` when
built by glibc. The checker accepts only the requested family and AArch64.

## Verification and mutation resistance

The carrier records mapped paths, device/inode, file size, relative retained
file names and SHA-256. The independent ordinary and rehydration checkers
recompute every retained-file digest and version marker; verify the helper ELF
machine and `PT_INTERP`; parse the retained maps text to bind each runtime path
and device/inode to an observed mapped row; bind the handoff role/image digest
to the exact source or Native Image; and require source and target runtime
family/version/path/file-digest facts to agree. Musl checking never invokes
`tls_runtime_identity.py`. A checksum-refreshed mutation to version, path,
loader/libc bytes or digests, helper interpreter/family, or source/target
identity disagreement must still fail semantic verification.

All `/proc` reads, JSON fields, retained files and aggregate runtime-identity
bytes are explicitly capped before allocation/read: maps are at most 1 MiB,
each maps line is at most 8192 bytes, each retained ELF is at most 32 MiB, the
identity JSON is at most 16 KiB, and all retained bytes for one native process
identity (maps, helper, libc, loader, and identity JSON) are at most 96 MiB.
Absolute mapped files remain strictly validated; unrelated kernel region names
such as `[heap]` or `[vdso]` are accepted only in bounded bracketed-label form
and can never satisfy a runtime-file identity. Ownership is proved twice. Each
file-backed maps interval must have exactly one fully containing page-rounded
`PT_LOAD` file interval with compatible permissions and one consistent load
bias. Subtracting that bias must then place the maps interval inside exactly one
fully containing page-rounded virtual interval derived from checked
`p_vaddr + p_memsz`, and this unique memory owner must be the same `PT_LOAD` as
the file owner. Reject every partial intersection or second virtual owner,
including aliases whose segments are file-disjoint and overlaps with zero-
`p_filesz` BSS segments. Use strict half-open intervals: adjacent pages are
valid; arithmetic or page-rounding overflow fails closed. Valid RELRO splits
remain accepted when each split has both unique owners.

The standalone rehydration evidence-root scanner uses no-follow,
descriptor-relative traversal after no-follow metadata checks. Its explicit
tree caps are 512 directories including the root, 1024 entries, 1000 files, and
256 MiB aggregate file bytes, in addition to the existing per-file bounds; root
and path components must not be symlinks. It rejects excess counts before
hashing or reading beyond the bound and rechecks tree identity during use.
Evidence helper modules are opened from the sibling path resolved through
`__file__`, with `O_NOFOLLOW`, a bounded regular-file read, and before/after
identity checks; checker/tests do not depend on ambient `PYTHONPATH`.

Failure to obtain an exact mapped regular file, stable same-descriptor
snapshot, supported version marker, correct helper interpreter, or complete
pair fails the evidence run; no runtime fallback is allowed. Historical glibc
roots without the carrier remain readable in default checker mode. Fresh
ordinary glibc runner checks and their independent exact-root CI invocations
must use the trusted `--require-runtime-identity` option; musl always requires
identity whether or not that option is supplied. The option is selected by the
runner invocation and is not derived from mutable evidence. Identity records
are always validated when present. Runtime choice is restricted to the
runner/checker evidence interface and is not a product/user compatibility
mode.

The carrier is evidence-only and is not a HostContext ABI extension. It proves
internal consistency between retained records and mapped ELF facts, not
cryptographic authenticity or resistance to a compromised producer/host; all
runtime identity fields are self-reported by the native process and then
independently checked against its retained bytes.

## Review checkpoint (2026-10-22)

The scoped independent review found no blocking findings. It verified the
page-rounded virtual-owner correction with ten focused `-Werror` C identity
self-test cases and four focused Python ownership/boundary tests, including
checksum-refreshed aliases, overflow, adjacent half-open pages, and RELRO
splits. Full Python discovery passed 487 tests with no skips; provider-positive
and provider-loaded rollback suites passed 29 and 8 tests respectively. The
retained ordinary-glibc indirect-control and provider-rollback roots, their
independent checkers, and exact SHA256SUMS manifests passed. The review used
current equivalent tests because the original probe logs were unavailable; no
repository files were changed by the reviewer.

This host has no `musl-gcc`, Docker, or Podman, so no live ordinary-musl E2E was
run. Hosted musl gate status remains pending. Do not promote musl, Bionic,
provider, shared-musl, or general indirect-control support from this local
review, and do not change historical evidence or task/PRD/registry state as a
substitute for hosted validation.
