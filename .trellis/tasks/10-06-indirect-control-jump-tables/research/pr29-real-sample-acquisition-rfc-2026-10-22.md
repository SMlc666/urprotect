# PR29 real-sample acquisition blockers: evidence and recovery options

**Research date:** 2026-10-22 (UTC)
**Scope:** Read-only investigation of the real-sample failures in PR #29, separate from the musl fixture/linker repair. No fixture, lock, expectation, checker, workflow, or product file was changed. No sample package was downloaded or executed. A bounded Alpine `APKINDEX.tar.gz` metadata response (501,435 bytes) was streamed and parsed in memory only.

## Executive finding

The two real-sample failures are **acquisition blockers, not ELF/parser/runtime regressions**:

1. **`nodejs` / Node.js, bionic:** the run's locked Termux `.deb` URL returned HTTP 404 on all four recorded curl attempts. The failing sample never reached fingerprinting or either required bionic execution oracle. The URL/path is internally consistent with the previously reviewed package lock and candidate provenance. A stale pin to a package no longer present in the rolling Termux pool is the leading explanation; an incorrect `archivePath` is unlikely. The historical CI log proves what that endpoint returned then, but current Termux HTTP checks could not be completed from this research environment (TLS failed before an HTTP response), so current repository absence is not independently proven.
2. **`alpine-libarchive` / libarchive-tools, musl:** the locked `3.8.3-r0` APK returned HTTP 404 on all four recorded CI attempts. A bounded current Alpine v3.22/aarch64 APK index now advertises `libarchive-tools 3.8.10-r0`, not `3.8.3-r0`; the exact `3.8.3-r0` URL also returned 404 from the independent `dl-4.alpinelinux.org` endpoint. This is strong evidence that an older package was removed from the active rolling branch, not a transient outage or malformed path.

Do **not** relabel either failure as expected, weaken the 100-identity gate, accept an unhashed “latest” archive, or treat this as a product compatibility result. First preference is to recover the original bytes by SHA-256 from a legitimate immutable source if one exists. If not, a version refresh requires a separately approved and fully reviewed lock/registry update. A durable content-addressed archive/cache is a longer-term reliability option, not a shortcut around provenance, license, hash, or sample gates.

## Evidence and causal classification

### 1. Node.js / Termux bionic (`projectId=nodejs`)

The failed PR artifact records:

- `fixtures/real-samples/manifest.json` pin: version `26.4.0-1`, path `pool/main/n/nodejs/nodejs_26.4.0-1_aarch64.deb`, URL `https://packages.termux.dev/apt/termux-main/pool/main/n/nodejs/nodejs_26.4.0-1_aarch64.deb`, SHA-256 `eaf3ed8a6e4b72ebaa8c2cb3bad778c577cdf9ea87ca91761213d8a3940fc090`, size `10,349,280` bytes.
- The same package identity/hash/size is bound in `fixtures/real-samples/bionic-node-runtime-lock.json`; the lock's `sourceArchiveLock` records the corresponding `packages.termux.dev` URL. The reviewed dependency row in that lock uses `packages-cf.termux.dev`; this is a distinct URL field, not evidence that the failed manifest URL had a bad path.
- The lock validator (`scripts/bionic_node_lock.py`) fixes the package version, filename, path, SHA, size, and source/lock URLs; it verifies the manifest package fields and that URL path and archive path agree. Candidate metadata came from workflow run `37105636258` (candidate artifact SHA-256 `ccd8022aef3671e4d0f33d9756adfbabd12bb057b1735732246887a155562f53`). That provenance supports that the pin was once a reviewed package candidate; it does **not** retain the archive bytes.
- Failed-run evidence is in `.artifacts/ci-investigation/pr29-run39752657696-20261022T091923Z-KF1OzJ/extracted/real-samples/pr/nodejs/`: `source.txt` confirms the exact URL/hash/size/version; `logs/acquisition.log` shows four `curl: (22) The requested URL returned error: 404` results (retries after 1, 2, and 4 seconds); `runtime-closure.json` says `environment-unavailable` / `archive download failed`; `result.json` has `firstFailureLayer=acquisition`, null source/runtime artifact hashes, and `environment-unavailable` for static, baseline, and outer-wrapper.
- The baseline and outer-wrapper policy remains `accepted-and-runs`. These are **not** passed, `not-applicable`, or Node.js execution outcomes; neither oracle ran.

**Cause assessment:** repeated HTTP 404 is different from a timeout, TLS error, 5xx, or one failed DNS lookup. The locked path has the expected Termux `pool/main/n/nodejs/<filename>` shape and agrees across manifest, lock, and prior candidate metadata, so a repo metadata/path typo is not supported by evidence. Termux's published mirror documentation describes a live repository and mirrors that replicate it, including a documented `rsync --delete` sync; it provides no historical-version retention promise. Therefore the most likely cause is that the pinned package version aged out of the current package pool (or its mirror), with moderate rather than conclusive confidence because no current Termux `Packages` index or successful current HEAD was available from this environment.

The secondary evidence error “runtime-closure lock digest differs from reviewed lock” is downstream fallout: the failed `runtime-closure.json` lacks `lockSha256` because package acquisition stopped. The checked-in `runtime-closures.json` value (`a21172380567011c490435ce2ea1dc9ed2d7f8e519be9c0071d0981a5e80e4fb`) binds the reviewed lock; this diagnostic does not itself establish that the reviewed digest is wrong.

### 2. Alpine libarchive-tools (`projectId=alpine-libarchive`)

The failed PR artifact records:

- Manifest pin: package `libarchive-tools`, version `3.8.3-r0`, path `main/aarch64/libarchive-tools-3.8.3-r0.apk`, URL `https://dl-cdn.alpinelinux.org/alpine/v3.22/main/aarch64/libarchive-tools-3.8.3-r0.apk`, SHA-256 `5b6fe56af810d2634996893c6a99bb67221e302ba6abc355611180ef798db1ae`, size `678,182` bytes.
- The source lock's index SHA is `1f7a5be0ef6c857f2aa1013f2be0b678d2c5dd2ad3a4eee5760a184be58bbe20`; the same source facts are recorded in `candidates.json` and summarized in `selection.md`.
- `.artifacts/ci-investigation/pr29-run39752657696-20261022T091923Z-KF1OzJ/extracted/real-samples/pr/alpine-libarchive/` contains the exact URL/hash/version in `source.txt`, four HTTP 404s in `logs/acquisition.log`, and a `result.json` with `firstFailureLayer=acquisition`, null source/runtime artifact hashes, and static `environment-unavailable`. In the PR tier the two dynamic layers are `not-applicable` for this sample; that does not exempt the required static/acquisition portion of the full registry.
- At **2026-10-22 05:02:04 UTC**, `https://dl-4.alpinelinux.org/alpine/v3.22/main/aarch64/APKINDEX.tar.gz` returned HTTP 200, `Last-Modified: Thu, 22 Oct 2026 05:02:04 GMT`, `Content-Length: 501435`, ETag `"6ad998cc-7a6bb"`. The bounded metadata body was 501,435 bytes; its locally computed SHA-256 was `e1b4f22b6a3486ae42790d660899c954cc18d120d40ae4cf710fe6b5aafc70bb`. Its `APKINDEX` member was 2,273,082 bytes. The `aarch64` record is `P:libarchive-tools`, `V:3.8.10-r0`, `S:693632`; the locked `3.8.3-r0` is absent. This is a live-index observation, **not** the checked-in lock/index digest and not an artifact used to execute or update the suite.
- A bounded HEAD of the exact old APK URL at `https://dl-4.alpinelinux.org/alpine/v3.22/main/aarch64/libarchive-tools-3.8.3-r0.apk` returned HTTP 404. The failed CI log independently records four 404s for the same filename on the configured `dl-cdn` host.

**Cause assessment:** high confidence that `3.8.3-r0` is no longer served from the active v3.22/aarch64 repository. The path matches the locked package name/version and the repository layout, and the current index points at a newer version. This is not explained by a temporary outage alone. Current direct `dl-cdn` HEAD from this research environment failed TLS before an HTTP status, so the 404 proof for that hostname is the retained CI log; the current mirror/index evidence is from `dl-4`.

## Official mirror / retention evidence

Termux's current official mirror documentation (`https://github.com/termux/termux-packages/wiki/Mirrors`, accessed 2026-10-22; page edit shown as 2026-10-16) identifies `packages.termux.dev` as the primary host, `packages-cf.termux.dev` as its Cloudflare endpoint, and describes other mirrors as copies of the primary repository, many operated by third parties and not guaranteed to remain available. It lists update frequencies, not an immutable historical-package service.

The official “How to mirror the official repositories” guide (`https://github.com/termux/termux-packages/wiki/How-to-mirror-the-official-repositories`, accessed 2026-10-22) gives `rsync -a --delete rsync://packages.termux.dev/termux termux` as the repository sync pattern. The `--delete` behavior is consistent with mirrors following the live repository rather than preserving superseded package archives. I found no published Termux guarantee that a once-current `.deb` remains addressable forever.

For Alpine, the active v3.22 package index is mutable in practice: the live index now names `3.8.10-r0`; exact `3.8.3-r0` returns 404 on `dl-4`. I found no evidence in this bounded check that an official old-package archive retains this exact APK. A HEAD to `archive.alpinelinux.org` could not be completed because the hostname did not resolve in this environment; historical archive availability therefore remains unverified. Do not infer from the active-repository 404 that no independent archive exists.

## Repository and CI behavior relevant to any later fix

- `fixtures/real-samples/README.md` defines exactly 100 distinct public identities, requires each tier to use the full registry, and says unavailable runtime closures are failures rather than expected results. PR dynamic execution has required witnesses for BusyBox/musl, GNU coreutils `ls`/glibc, and Node.js/bionic; all 100 still need their required acquisition/static path. `scripts/validate-real-samples.py` and `scripts/validate-runtime-closures.py` enforce the 100-project registry and the runtime/lock chain.
- `scripts/run-real-sample-matrix.sh` downloads the exact manifest URL using bounded curl and then checks the archive SHA-256 before extraction. On acquisition failure it emits `environment-unavailable` and returns failure. The current `--retry 3 --retry-all-errors` produces four requests for persistent 404s; retry behavior cannot recover a removed object and must not substitute a different package.
- Source packages are downloaded as per-project `sample_tmp/source.archive` and removed with the temporary tree; raw package archives are not uploaded as CI evidence. The existing failed real-sample artifact ZIP has 2,119 members and no `.deb` or `.apk` package members. `fixtures/real-samples/README.md` explicitly says raw input archives/binaries are never retained in the repository or evidence upload.
- The workflow `.github/workflows/ci.yml` caches `${RUNNER_TEMP}/urprotect-real-sample-package-cache/archives` and `/indexes` with a key derived from the locks, registry and closure tooling. This is a best-effort GitHub Actions cache, not a documented durable archive. In particular, the Node.js source archive is the per-sample `source.archive`; `bionic_node_runner.py` skips downloading the `nodejs` row as a dependency archive and only caches its other locked dependency packages. A prior cache hit may help a dependency, but this run has no retained Node source bytes in its evidence artifact.
- The failed artifact is acquisition-only. It does not establish Node.js bionic execution, Alpine libarchive behavior, or an ELF regression.

## Recovery options (design only; no changes authorized here)

| Option | What it preserves | Required controls / tradeoff |
|---|---|---|
| **A. Byte-preserving immutable mirror (preferred first probe)** | Keeps existing sample version, SHA-256 and expected inputs unchanged. | Locate the original object in an approved source/cache. Only republish/repoint if exact bytes are proven to match the locked size and SHA-256, and package license/provenance permit it. Use a versioned or digest-addressed immutable URL, not a mutable `latest` URL. An alternate Termux mirror is useful only if it actually serves the expected object; documented mirror rotation is not archival retention. Update all URL fields/validators consistently if the chosen mirror is encoded in the lock. This minimizes compatibility-baseline drift.
| **B. Reviewed upstream version refresh** | Keeps the same public project identity, but changes package bytes/version and potentially ELF or dependency facts. | Separate explicit approval and PR. Resolve from a reviewed current package index; bind URL/path/version/size/SHA and package checksum to that exact index; reacquire/inspect/test the exact object under the existing bounds. Refresh the full Termux dependency closure and verify against the pinned image inventory; update Alpine runtime dependency selection/index lock. Review new fingerprints and existing execution expectations. Never turn this into “download whatever is latest” or a `not-applicable` result.
| **C. Durable content-addressed archive/cache** | Prevents future disappearance of exact locked inputs and reduces dependence on upstream pool retention. | Design an approved, immutable package-input store keyed by SHA-256 with retained URL/version/index provenance, size, license and integrity metadata. Keep raw package blobs outside the evidence tree and outside normal CI artifact uploads; ensure retention, access control and third-party license permissions. A GitHub Actions cache alone is evictable/best-effort and is not a durable archive. Make the CI cache a verified accelerator, never trust it without the same size/hash check.

**Small recommendation needing approval:** authorize a bounded search for the exact original Node and Alpine blobs by their existing hashes, followed by a reviewed digest-pinned mirror only if the bytes and redistribution provenance match. If either exact blob cannot be found, stop and request approval for a separate version-refresh/archive-policy task; do not change this task's fixtures, lock or expected outcomes. The durable content-addressed store is a follow-up design decision.

## Files and cross-lock updates to plan only after approval

If the exact bytes are found and only their immutable source URL changes, update the appropriate URL fields and their validators while keeping the current version, SHA-256 and size. For a version refresh, expect at least:

- **Node.js:** `fixtures/real-samples/manifest.json`; its duplicate candidate row in `fixtures/real-samples/candidates.json`; `fixtures/real-samples/bionic-node-runtime-lock.json` (source archive and any changed dependencies/base inventory); `scripts/bionic_node_lock.py` (version/path/hash/size and expected package metadata); `fixtures/real-samples/runtime-closures.json` (`nodejsLockSha256`, and image identity only if the lock/image changes); `tests/test_bionic_node_runtime_lock.py` and `tests/test_bionic_node_closure.py`; `fixtures/real-samples/selection.md`; regenerate the metadata-only baseline aggregate if the registry input changes.
- **Alpine libarchive:** `fixtures/real-samples/manifest.json` plus duplicate selected candidate in `fixtures/real-samples/candidates.json`; the source index observations and, if the runtime index/dependencies change, `fixtures/real-samples/runtime-closures.json` (`registryObservationIndexSha256` and/or `packageIndexSha256`); package metadata/checksum and any updated expected fingerprint; `fixtures/real-samples/selection.md`; baseline aggregate regeneration if registry fields change.
- **Shared registry chain:** update `fixtures/evaluator/compatibility-corpus.json` public-real-sample manifest SHA after the manifest is reviewed; keep the 100 distinct IDs unchanged unless separately approved. Re-run the metadata validators/tests, regenerate checked-in metadata-only baseline artifacts from the reviewed registry, and run the full required CI real-sample matrix. Required evidence must still report Node.js baseline and outer-wrapper `accepted-and-runs` and static validation for all 100; no old failure may be silently accepted as expected-unavailable.
- **If archival/cache infrastructure is chosen:** separately update CI workflow/cache ownership, tests, retention/provenance documentation, and evidence sanitization assumptions. The archive remains a source-input facility, not an uploaded raw sample evidence artifact.

Useful future validation commands (not run in this research-only assignment):

```sh
python3 scripts/validate-real-samples.py fixtures/real-samples/manifest.json \
  --candidates fixtures/real-samples/candidates.json --tier pr
python3 scripts/validate-runtime-closures.py \
  fixtures/real-samples/runtime-closures.json fixtures/real-samples/manifest.json
python3 tests/test_real_sample_manifest.py
python3 tests/test_real_sample_fingerprint.py
python3 tests/test_real_sample_evidence.py
python3 tests/test_bionic_node_runtime_lock.py
python3 tests/test_bionic_node_closure.py
```

These metadata/tests are not a substitute for an authorized full ARM64 CI run. No CI rerun, retry, fixture/lock change, baseline promotion, task creation, install, commit, push, or merge was done here.

## Limitations / residual risks

- Current HTTPS HEAD requests to Termux primary and listed mirrors failed locally with TLS EOF before HTTP status. The PR artifact's four 404s are valid historical endpoint evidence, but current Termux index/file availability cannot be independently confirmed here. Do not call those local TLS failures 404s.
- `archive.alpinelinux.org` DNS resolution failed, so this check neither found nor ruled out an independent historic Alpine archive. The active v3.22 repository evidence is sufficient to classify the stale pin there, not to prove the exact bytes are unrecoverable.
- No old/new package binary was downloaded, hashed, unpacked, or executed in this investigation. All package SHA/size values other than the current APKINDEX are reviewed lock metadata, not independently revalidated package bytes.

## Sources

- Existing failed-run handoff: `/tmp/pr29-ci-failure-investigation-and-repair.md` (PR #29 run `39752657696`; retained artifact ZIP/listing hashes and bounded extraction review).
- Existing CI evidence root: `.artifacts/ci-investigation/pr29-run39752657696-20261022T091923Z-KF1OzJ/` (real-sample archive and per-sample logs noted above).
- Termux mirror facts: [Termux package mirrors](https://github.com/termux/termux-packages/wiki/Mirrors); [How to mirror the official repositories](https://github.com/termux/termux-packages/wiki/How-to-mirror-the-official-repositories).
- Alpine live metadata and exact old-object probe: [v3.22 main/aarch64 APKINDEX](https://dl-4.alpinelinux.org/alpine/v3.22/main/aarch64/APKINDEX.tar.gz); [locked libarchive-tools 3.8.3-r0 URL](https://dl-4.alpinelinux.org/alpine/v3.22/main/aarch64/libarchive-tools-3.8.3-r0.apk) (HEAD 404 at the recorded research time).
- Internal contract/context: `fixtures/real-samples/README.md`, `fixtures/real-samples/manifest.json`, `fixtures/real-samples/candidates.json`, `fixtures/real-samples/runtime-closures.json`, `fixtures/real-samples/bionic-node-runtime-lock.json`, `scripts/run-real-sample-matrix.sh`, `scripts/bionic_node_runner.py`, `scripts/build-runtime-closure.py`, `.github/workflows/ci.yml`.
