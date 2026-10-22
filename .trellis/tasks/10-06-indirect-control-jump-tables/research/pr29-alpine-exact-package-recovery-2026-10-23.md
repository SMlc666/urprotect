# PR #29 Alpine `libarchive-tools` exact-package recovery — 2026-10-23

> Historical note: the initial bounded probe and conservative recommendation below predate the parent's later authentication of the exact signed index and package. The authenticated follow-up at the end supersedes its tentative 3.8.10 provenance caution and refresh recommendation.

## Initial bounded-probe finding (superseded by authenticated follow-up below)

**The locked `3.8.3-r0` APK was not recovered.** No exact-byte response was obtained from the official Alpine archive/CDN or the bounded set of established mirrors. The observations support “not available at these endpoints now,” not “unrecoverable everywhere.” Do not change the lock on this evidence alone.

The safest immediate action is to preserve the existing lock and continue to treat PR #29 as blocked at acquisition. If a separately approved, controlled version refresh is chosen, `3.8.10-r0` is a candidate, not an already-approved replacement: this investigation fetched and hashed its bytes from the `dl-4` mirror, but did not verify the Alpine index signature or extract/review the executable. The complete registry/index cross-update and runtime revalidation described below are required; no product/runtime support claim follows from this research.

## Locked item and bounded probe accounting

Locked input:

- `https://dl-cdn.alpinelinux.org/alpine/v3.22/main/aarch64/libarchive-tools-3.8.3-r0.apk`
- `678,182` bytes; expected SHA-256 `5b6fe56af810d2634996893c6a99bb67221e302ba6abc355611180ef798db1ae`
- Existing registry source-index SHA-256: `1f7a5be0ef6c857f2aa1013f2be0b678d2c5dd2ad3a4eee5760a184be58bbe20`

Exactly **12 bounded HTTP/index probes** were used; no recursive crawl or hash-lookup page was used. HEAD checks were made without following redirects. GETs were capped (`APKINDEX.tar.gz` at 2 MiB; APK at 2,000,000 bytes). No GET was made for the locked APK because no locked-APK HEAD returned 200.

| # | URL / target | Result |
|---:|---|---|
| 1 | `https://archive.alpinelinux.org/alpine/v3.22/main/aarch64/libarchive-tools-3.8.3-r0.apk` | No HTTP response; DNS resolution failed (`curl 6`). |
| 2 | Locked `dl-cdn.alpinelinux.org` 3.8.3 APK URL | No HTTP response; TLS EOF (`curl 35`), not a 404. |
| 3 | `https://dl-4.alpinelinux.org/alpine/v3.22/main/aarch64/libarchive-tools-3.8.3-r0.apk` | HTTP 404, TLS verification succeeded. |
| 4 | TUNA exact 3.8.3 path | HTTP 404, TLS verification succeeded. |
| 5 | USTC exact 3.8.3 path | HTTP 302 to the locked `dl-cdn` URL; no redirect follow. |
| 6 | Aliyun exact 3.8.3 path | HTTP 404, TLS verification succeeded. |
| 7 | SJTUG exact 3.8.3 path | HTTP 302 to `mirror.sjtu.edu.cn`; no redirect follow. |
| 8 | `https://dl-cdn.alpinelinux.org/alpine/v3.22/main/aarch64/APKINDEX.tar.gz` | No HTTP response; TLS EOF (`curl 35`). This is the URL for the runtime-index lock, not a file response. |
| 9 | Official CDN `libarchive-tools-3.8.10-r0.apk` | No HTTP response; TLS EOF (`curl 35`). |
| 10 | `https://dl-4.alpinelinux.org/alpine/v3.22/main/aarch64/APKINDEX.tar.gz` | HTTP 200; 501,435 bytes; SHA-256 `e1b4f22b6a3486ae42790d660899c954cc18d120d40ae4cf710fe6b5aafc70bb`; `Last-Modified: Thu, 22 Oct 2026 05:02:04 GMT`. The tar contains `APKINDEX` (2,273,082 bytes; member SHA-256 `9d4e163f9f1c01080afd02d302e8f81097b38194ca11808606b5eff314c60a09`) and an Alpine-named RSA signature member. The signature was **not** cryptographically verified (no local Alpine keyring/verifier was available). |
| 11 | `https://dl-4.alpinelinux.org/alpine/v3.22/main/aarch64/libarchive-tools-3.8.10-r0.apk` | HTTP 200; 693,632 bytes; SHA-256 `8d02a3e2d9bbd9d6718bfa1a9c7773cecaf8f46a1b54cedae8ac433cd84478ee`; `Last-Modified: Sun, 18 Oct 2026 10:47:25 GMT`; TLS verification succeeded. This is a locally measured digest of retrieved bytes, not a previously reviewed lock. |
| 12 | `https://mirror.sjtu.edu.cn/alpine/v3.22/main/aarch64/libarchive-tools-3.8.3-r0.apk` (SJTUG redirect target) | HTTP 404, TLS verification succeeded. |

The reachable mirror responses had HTTP `Date` headers on 22 October 2026 even though this request was assigned the date 23 October. Treat the index above as the measured 22-October mirror snapshot, not as proof of a newer 23-October repository state.

### Provenance limits

The 3.8.10 archive was obtained from the Alpine `dl-4` repository path over verified HTTPS, and the separately downloaded APKINDEX from the same mirror names package `libarchive-tools`, version `3.8.10-r0`, architecture `aarch64`, size `693632`, origin `libarchive`, license `BSD-2-Clause AND BSD-3-Clause AND Public-Domain`, and APK-index checksum `Q1h09YexAZ0bqSAwneLYDp3lj46tQ=`. The index size equals the measured APK size. The package itself was SHA-256 hashed locally. However, the index signature was not verified and the APK was not checked with Alpine's package-signature tooling. Therefore this is useful recovery/refresh evidence, **not yet a fully publisher-attested replacement lock**. Do not trust a third-party-advertised hash; finish provenance/signature and package review before promotion.

## Compatibility against the currently reachable v3.22/aarch64 index

The fetched mirror index (`e1b4f22b…`) is not equal to either checked-in Alpine digest: the registry/candidate-source index (`1f7a5be0…`) or the runtime resolver index (`4d5e7550…`). The exact checked-in runtime index bytes were not present in the repository/local probe cache, and the official CDN index request failed TLS. Thus the table below establishes compatibility with the **reachable 22-October index**, not with the exact `4d5e7550…` runtime-index object.

For each selected Alpine row, I compared its recorded package name/version, APKINDEX `C` checksum, and archive byte size against the downloaded index. **19/20** existing package rows match all three fields exactly. The one changed row is `alpine-libarchive`: old version/checksum/size is absent; current is `3.8.10-r0`, `C=Q1h09YexAZ0bqSAwneLYDp3lj46tQ=`, `S=693632`.

| Project | Locked version | Reachable index version | Existing `C` and `S` match? |
|---|---|---|---|
| `alpine-7zip` | `24.09-r0` | `24.09-r0` | yes |
| `alpine-apk-tools` | `2.14.12-r0` | `2.14.12-r0` | yes |
| `alpine-bc` | `1.08.2-r0` | `1.08.2-r0` | yes |
| `alpine-diffutils` | `3.12-r0` | `3.12-r0` | yes |
| `alpine-dosfstools` | `4.2-r2` | `4.2-r2` | yes |
| `alpine-ed` | `1.21-r0` | `1.21-r0` | yes |
| `alpine-fish` | `4.0.2-r0` | `4.0.2-r0` | yes |
| `alpine-fping` | `5.3-r0` | `5.3-r0` | yes |
| `alpine-fsarchiver` | `0.8.8-r0` | `0.8.8-r0` | yes |
| `alpine-libarchive` | `3.8.3-r0` | `3.8.10-r0` | **no** |
| `alpine-mandoc` | `1.14.6-r13` | `1.14.6-r13` | yes |
| `alpine-mc` | `4.8.33-r2` | `4.8.33-r2` | yes |
| `alpine-memcached` | `1.6.32-r0` | `1.6.32-r0` | yes |
| `alpine-openssh` | `10.0_p1-r10` | `10.0_p1-r10` | yes |
| `alpine-parted` | `3.6-r2` | `3.6-r2` | yes |
| `alpine-patch` | `2.8-r0` | `2.8-r0` | yes |
| `alpine-patchelf` | `0.18.0-r3` | `0.18.0-r3` | yes |
| `alpine-dropbear` | `2025.88-r1` | `2025.88-r1` | yes |
| `alpine-zstd` | `1.5.7-r0` | `1.5.7-r0` | yes |
| `alpine-bluez` | `5.82-r0` | `5.82-r0` | yes |

The `C`/`S` comparison proves the 19 unchanged rows are still represented identically in this fetched index; it does not re-fetch or re-hash their APK blobs. The 3.8.10 archive digest above likewise does not substitute for the index-signature/package-signature review.

## Minimum coherent refresh contract if maintainers approve 3.8.10-r0

Do not patch only one URL/hash. The current validators tie every selected APK row to one global Alpine candidate-index digest, and `alpine-libarchive` has nightly/release baseline and outer-wrapper requirements (`accepted-and-runs`). A controlled refresh must cover these contracts:

1. **Registry source row and static identity:** in `fixtures/real-samples/manifest.json`, replace the `alpine-libarchive` version/path/URL, archive SHA-256 (`8d02…` only after provenance review), size `693632`, package checksum `Q1h09Y…`, source-index SHA, and `licenseSource` index digest. Reacquire and review the executable inside the APK: `artifactPath`, extracted ELF SHA/size, ELF fingerprint fields, bounded-extraction local byte count, and managed static-validation evidence must be regenerated; do not assume the old `bsdtar` artifact identity/facts remain valid.
2. **One index identity for all 20 selected APKs:** the manifest's `corpus.expansion.increment.alpineIndexSha256` is `1f7a5be0…`; `scripts/validate-real-samples.py` requires each APK row's `provenance.sourceIndexSha256` to equal that global value. If the approved new observation index is the measured `e1b4f22…` index, update the digest for **all 20** Alpine source rows and the corresponding `licenseSource` index references, not just libarchive. The other 19 rows' version, index `C` and `S` stay compatible according to the comparison above; their archive SHA/size locks should remain unchanged unless separately re-acquired and reviewed.
3. **Candidate cross-check and registry review:** mirror the selected-row update in `fixtures/real-samples/candidates.json`, including all source-index references, the libarchive package facts and regenerated fingerprint, `review.archiveIndexSha256`, and `registryReview.alpineIndexSha256`. Keep the 100 distinct identity count and project IDs unchanged. The manifest/candidate selected row hash cross-checks must pass.
4. **Runtime-index split and actual execution:** `fixtures/real-samples/runtime-closures.json` currently pins `runtimes.musl.registryObservationIndexSha256=1f7a5be0…` separately from `packageIndexSha256=4d5e75508936b08bed7423bb9e9039a669eadc05323189a9c31c90573766ab99`. Update the registry-observation digest if the source index changes. Do **not** silently equate it with the runtime `packageIndexSha256`. The exact `4d5e…` index was unavailable in this probe set, so whether it contains 3.8.10 is unverified. Prove the new package can be resolved from that exact pinned index or deliberately repin to an approved index and regenerate/revalidate the musl runtime closures. Preserve `alpine-libarchive` baseline and outer-wrapper `accepted-and-runs` policy; verify both on native AArch64 CI with the refreshed package and closure.
5. **Human-readable registry and evaluator digest chain:** update the Alpine index digest and package/version entry in `fixtures/real-samples/README.md` and `fixtures/real-samples/selection.md`. `fixtures/evaluator/compatibility-corpus.json` currently pins the manifest SHA-256 as `600b6ed362d440bab32eae7632899d40cdf607c0926150399477f057f0badabf`; recompute it after the reviewed manifest change and update that pin. Regenerate `fixtures/real-samples/baseline-aggregate.json` only from appropriate refreshed CI evidence; the prior acquisition failure is not compatibility evidence.
6. **Validation gates:** rerun `scripts/validate-real-samples.py` with the candidate ledger, `scripts/validate-runtime-closures.py`, manifest/fingerprint/evidence tests (`tests/test_real_sample_manifest.py`, `tests/test_real_sample_fingerprint.py`, `tests/test_real_sample_evidence.py`), and full required native ARM64 sample CI. Do not change expected runtime outcomes to `not-applicable` or `environment-unavailable` to accommodate the acquisition issue.

The existing global pins to carry through review are:

- Registry/candidate discovery index: `1f7a5be0ef6c857f2aa1013f2be0b678d2c5dd2ad3a4eee5760a184be58bbe20` → candidate new observed index `e1b4f22b6a3486ae42790d660899c954cc18d120d40ae4cf710fe6b5aafc70bb` (new value only after approved index review).
- Runtime closure `packageIndexSha256`: `4d5e75508936b08bed7423bb9e9039a669eadc05323189a9c31c90573766ab99` (different input; exact bytes not checked in this bounded run).
- Compatibility-corpus pin of `fixtures/real-samples/manifest.json`: current SHA-256 `600b6ed362d440bab32eae7632899d40cdf607c0926150399477f057f0badabf`; recompute after any manifest change.

## Guardrails and residual uncertainty

- No `3.8.3-r0` body was received, so there is no reportable new HTTP status/byte count/SHA-256 for the exact artifact. The expected `5b6fe…` hash remains only the existing reviewed pin.
- The official archive hostname DNS failure and official CDN TLS errors are environmental observations, not proof of global absence. Four reachable mirror paths returned 404; USTC redirected to the blocked CDN.
- The currently pinned runtime APKINDEX (`4d5e…`) was not fetched or locally available; the 19/20 matrix is for the reachable `e1b4f22…` snapshot only. The source-index pin (`1f7a…`) and runtime package-index pin (`4d5e…`) are separate contracts.
- The downloaded 3.8.10 package and index were used only for bounded local size/hash/metadata inspection, were not installed, extracted, or executed, and the temporary probe downloads were removed. No source, lock, selection, expectation, task status, or runtime-support claim was changed.
- `python3 ./.trellis/scripts/task.py current --source` returned `(none)` in this session; the explicit task path supplied in the request was used for this research addendum without changing task state.

## Authenticated controlled-refresh follow-up (2026-10-23)

The parent directly verified and authenticated the exact current Alpine v3.22/aarch64 source artifacts. This resolves the earlier provenance uncertainty above and authorizes the narrow source/closure lock refresh; it does not authorize a runtime-compatibility promotion.

- Exact signed `APKINDEX.tar.gz`: 501,435 bytes, SHA-256 `e1b4f22b6a3486ae42790d660899c954cc18d120d40ae4cf710fe6b5aafc70bb`, from `https://dl-4.alpinelinux.org/alpine/v3.22/main/aarch64/APKINDEX.tar.gz`. Its APKINDEX signature verified as `Verified OK` over the exact signed compressed member bytes using the official Alpine 3.22-stable key `alpine-devel@lists.alpinelinux.org-616ae350.rsa.pub`; signature member names matched (RSA/SHA-1).
- The signed index's unique `libarchive-tools` aarch64 row is `V=3.8.10-r0`, `S=693632`, `C=Q1h09YexAZ0bqSAwneLYDp3lj46tQ=`, origin `libarchive`, license `BSD-2-Clause AND BSD-3-Clause AND Public-Domain`. The exact archive from the corresponding `dl-4` repository path is 693,632 bytes, SHA-256 `8d02a3e2d9bbd9d6718bfa1a9c7773cecaf8f46a1b54cedae8ac433cd84478ee`; the TUNA response independently had the same SHA-256. The APK signature also verified `Verified OK` against the exact signed compressed member bytes with the same official key. `PKGINFO.datahash` matches the compressed data member, and the signed index `C` equals the `Q1` prefix plus base64(SHA-1(compressed control member)).
- Bounded extraction/inspection of that exact archive passed. `usr/bin/bsdtar` is 657,448 bytes, SHA-256 `265f3e0964973feb1dca883a109616b22a37f4745baf3b6ada4fda7be6bc3289`, build ID `36c1152ca47ef606893a2ac6d44306b8cb820df8`. Project fingerprint inspection/comparison and managed structural validation passed (exit 0). No runtime execution occurred.
- The parent-verified isolated `build-runtime-closure.py` run, using this exact signed index and the official `dl-4` repository root, succeeded with 10 package entries including `libarchive-tools 3.8.10-r0`; it did not execute target code. The runtime closure lock now pins this same index and root as the registry source observation. Existing baseline/outer-wrapper expected behavior and status remain unchanged; the source refresh itself is not musl runtime evidence.
- A literal repository/evidence search performed before this addendum found no artifact containing the alternate APK checksum or package-size figures; there is no path/source to report. Those figures are neither the signed index record nor the authenticated archive bytes and do not override these facts.
- Preserve the earlier Node.js URL repair and unrelated dirty files. Keep the current scoped support/runtime status unchanged and require the normal hosted evidence gates before any separate compatibility decision.
