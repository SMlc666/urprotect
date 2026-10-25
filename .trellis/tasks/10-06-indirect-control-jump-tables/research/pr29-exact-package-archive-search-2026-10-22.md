# PR #29 exact package archive search — 2026-10-22

## Result

A byte-for-byte copy of the locked Termux Node.js package was recovered from **two mirrors listed by Termux's official mirror roster**. Both responses were HTTPS/TLS-verified, both files had the locked length and SHA-256, and no package contents were extracted, unpacked, executed, or installed. The copies are retained only in the private `/tmp` directory listed below. This is sufficient to prove the original bytes are available from those endpoints now; it does **not** establish an immutable archive or grant permission to redistribute the package.

The locked Alpine `libarchive-tools` APK was **not** recovered in this bounded search. The official Alpine archive hostname did not resolve in this environment; live mirrors produced 404, a redirect back to the official CDN followed by a TLS failure, or TLS failures before an HTTP response. These outcomes do not prove that the exact APK is unrecoverable elsewhere.

No project files other than this requested research addendum were written. No URL, fixture, lock, expected value, CI workflow, task state, or existing RFC/journal was changed.

## Scope and limits

The search was limited to exact, pinned package paths at official Termux mirrors and a small set of Alpine archive/package-mirror endpoints. HEAD was attempted first for every blob URL. A GET was performed only when HEAD returned HTTP 200. Each GET was capped at the exact pinned package size; resulting bytes were retained only when both size and SHA-256 matched the lock. There were six Termux endpoint attempts and seven Alpine endpoint attempts, within the requested maximum of 12 per artifact. No generic search engines, arbitrary file-hosting sites, untrusted hash-lookup services, or unrestricted internet scraping were used.

`python3 ./.trellis/scripts/task.py current --source` returned `Current task: (none)` / `Source: none` (exit code 1). The user supplied the task directory explicitly, so research was confined to that path without changing task status.

## Node.js Termux package — exact match found

### Locked identity

The prior RFC records this pin from `fixtures/real-samples/manifest.json` and `bionic-node-runtime-lock.json`:

- Filename: `nodejs_26.4.0-1_aarch64.deb`
- Version: `26.4.0-1`
- Original URL: `https://packages.termux.dev/apt/termux-main/pool/main/n/nodejs/nodejs_26.4.0-1_aarch64.deb`
- Expected size: **10,349,280 bytes**
- Expected SHA-256: **`eaf3ed8a6e4b72ebaa8c2cb3bad778c577cdf9ea87ca91761213d8a3940fc090`**

The existing RFC says this package identity and digest were bound to the reviewed lock and prior candidate metadata. The current searches verify the bytes against that pinned digest; they do not independently reproduce the earlier candidate review or prove archive history.

### Exact-byte GETs

| Source | Final URL | GET result and retrieval time (UTC) | Redirects / TLS | Bytes and SHA-256 | Private retained path |
|---|---|---|---|---|---|
| Tsinghua University TUNA mirror | `https://mirrors.tuna.tsinghua.edu.cn/termux/apt/termux-main/pool/main/n/nodejs/nodejs_26.4.0-1_aarch64.deb` | HTTP/2 200; request `2026-10-22T13:43:43Z`; response Date `2026-10-22 13:43:44 GMT` | 0 redirects; TLS certificate verification result 0 (verified) | 10,349,280; exact expected SHA-256 | `/tmp/pr29-exact-package-search-20261022-rzeejG/tuna-nodejs_26.4.0-1_aarch64.deb` |
| University of Science and Technology of China (USTC) mirror | `https://mirrors.ustc.edu.cn/termux/termux-main/pool/main/n/nodejs/nodejs_26.4.0-1_aarch64.deb` | HTTP/2 200; request `2026-10-22T13:43:45Z`; response Date `2026-10-22 13:43:47 GMT` | 0 redirects; TLS certificate verification result 0 (verified) | 10,349,280; exact expected SHA-256 | `/tmp/pr29-exact-package-search-20261022-rzeejG/ustc-nodejs_26.4.0-1_aarch64.deb` |

Both GETs used `curl --max-filesize 10349280`. Both server responses declared `Content-Length: 10349280` and `Last-Modified: Fri, 14 Aug 2026 22:23:13 GMT`; both advertised ETag `"6a7f9551-9deae0"`. Each downloaded file was then measured and hashed locally. The two successful transfers are corroborating serving endpoints, but they may be synchronized copies and are not independent proof of historical provenance.

### Other bounded Termux HEAD probes

All candidate paths below used the exact filename and relative pool path above. Requests were made on 2026-10-22 UTC, used HTTPS, had zero redirects, and stopped at HEAD; no package bytes were fetched from these endpoints.

| Source | HEAD time | Result | TLS / notes |
|---|---|---|---|
| Termux primary, `https://packages.termux.dev/apt/termux-main/pool/main/n/nodejs/nodejs_26.4.0-1_aarch64.deb` | 13:43:12 | No HTTP response (`http=000`) | curl exit 35; TLS connection ended unexpectedly before an HTTP status |
| Termux Cloudflare endpoint, `https://packages-cf.termux.dev/apt/termux-main/pool/main/n/nodejs/nodejs_26.4.0-1_aarch64.deb` | 13:43:13 | No HTTP response (`http=000`) | curl exit 35; TLS connection ended unexpectedly before an HTTP status |
| Tsinghua TUNA mirror, successful GET URL above | 13:43:15 | HTTP/2 200; `Content-Length: 10349280` | TLS verified; no redirect |
| USTC mirror, successful GET URL above | 13:43:16 | HTTP/2 200; `Content-Length: 10349280` | TLS verified; no redirect |
| mwt mirror, `https://mirror.mwt.me/termux/main/pool/main/n/nodejs/nodejs_26.4.0-1_aarch64.deb` | 13:43:16 | No HTTP response (`http=000`) | curl exit 35; TLS connection ended unexpectedly before an HTTP status |
| Academic Computer Club mirror, `https://mirror.accum.se/mirror/termux.dev/termux-main/pool/main/n/nodejs/nodejs_26.4.0-1_aarch64.deb` | 13:43:18 | No HTTP response (`http=000`) | curl exit 35; TLS connection ended unexpectedly before an HTTP status |

The TLS failures above are **not** 404s. Likewise, the prior CI run's recorded 404s at the primary URL remain historical evidence and are not substituted for these current responses.

### Provenance, mirror policy, and license status

- At `2026-10-22T13:45:55Z`, the Termux official mirror roster page returned HTTP 200 over verified TLS: <https://github.com/termux/termux-packages/wiki/Mirrors>. It lists both TUNA and USTC with the repository paths used above. The page identifies `packages.termux.dev` as the primary repository and was marked edited 2026-10-16 when accessed.
- At `2026-10-22T13:45:58Z`, Termux's official mirroring instructions returned HTTP 200 over verified TLS: <https://github.com/termux/termux-packages/wiki/How-to-mirror-the-official-repositories>. It instructs mirrors to synchronize with `rsync -a --delete` from the live package repository. That is a live-mirror model, not a promise to preserve superseded package versions. The two exact package copies are therefore from **mutable mirrors**, not demonstrated immutable archives.
- The locked hash and size provide strong byte identity with the existing reviewed pin. The mirror roster establishes that the endpoints are listed Termux mirrors. Neither establishes that the package is retained permanently, that the two mirrors have independent custody, or that the package may be republished.
- **No package-license or redistribution review was performed.** The binary was deliberately not extracted to inspect its metadata or license files. Keep these private `/tmp` copies as research evidence only; do not claim redistribution permission or repoint CI to either URL until provenance and licensing are separately reviewed.

## Alpine `libarchive-tools` — not found in bounded search

### Locked identity

The prior RFC records this pin from the real-sample manifest and source lock:

- Filename: `libarchive-tools-3.8.3-r0.apk`
- Version: `3.8.3-r0`
- Original URL: `https://dl-cdn.alpinelinux.org/alpine/v3.22/main/aarch64/libarchive-tools-3.8.3-r0.apk`
- Expected size: **678,182 bytes**
- Expected SHA-256: **`5b6fe56af810d2634996893c6a99bb67221e302ba6abc355611180ef798db1ae`**

No Alpine response returned HTTP 200, so no GET was performed and no APK bytes were downloaded or retained.

### Bounded Alpine HEAD probes

| Source URL | HEAD request time (UTC) | Result | Redirects / TLS / details |
|---|---|---|---|
| Official Alpine archive: `https://archive.alpinelinux.org/alpine/v3.22/main/aarch64/libarchive-tools-3.8.3-r0.apk` | 13:44:15 | No HTTP response (`http=000`) | curl exit 6; DNS could not resolve `archive.alpinelinux.org`; no TLS handshake or HTTP response |
| Locked official CDN URL: `https://dl-cdn.alpinelinux.org/alpine/v3.22/main/aarch64/libarchive-tools-3.8.3-r0.apk` | 13:44:15 | No HTTP response (`http=000`) | curl exit 35; TLS EOF before HTTP response |
| Alpine `dl-4` mirror: `https://dl-4.alpinelinux.org/alpine/v3.22/main/aarch64/libarchive-tools-3.8.3-r0.apk` | 13:44:17 | HTTP/2 404; response Date `2026-10-22 13:44:19 GMT`; declared content length 153 bytes | 0 redirects; TLS verified (curl TLS verification result 0) |
| AARNet mirror: `https://mirror.aarnet.edu.au/pub/alpine/v3.22/main/aarch64/libarchive-tools-3.8.3-r0.apk` | 13:44:19 | No HTTP response (`http=000`) | curl exit 35; TLS EOF before HTTP response |
| Kernel.org mirror: `https://mirrors.edge.kernel.org/alpine/v3.22/main/aarch64/libarchive-tools-3.8.3-r0.apk` | 13:44:21 | No HTTP response (`http=000`) | curl exit 35; TLS EOF before HTTP response |
| Tsinghua TUNA mirror: `https://mirrors.tuna.tsinghua.edu.cn/alpine/v3.22/main/aarch64/libarchive-tools-3.8.3-r0.apk` | 13:45:25 | HTTP/2 404; response Date `2026-10-22 13:45:26 GMT`; declared content length 153 bytes | 0 redirects; TLS verified (curl TLS verification result 0) |
| USTC Alpine path: `https://mirrors.ustc.edu.cn/alpine/v3.22/main/aarch64/libarchive-tools-3.8.3-r0.apk` | 13:45:26 | Initial HTTP/2 302; `Location` redirected to the exact `dl-cdn.alpinelinux.org` URL above, after which curl ended with `http=000` | 1 redirect; TLS verified for the redirect response, then TLS EOF at the destination; no package body received |

### Provenance, archive status, and license status

The Alpine archive could not be inspected because its hostname did not resolve. The reachable `dl-4` and TUNA paths behaved as live package mirrors and returned 404 for the old filename. USTC redirected to the current official CDN URL rather than serving the object itself. No immutable snapshot or content-addressed public store for this APK was identified in the bounded source review. These observations do not rule out another historical archive or a trusted private cache.

The prior acquisition RFC reports that the current Alpine v3.22/aarch64 package index advertises `libarchive-tools 3.8.10-r0`, that the locked `3.8.3-r0` is absent from that live index, and that CI recorded four 404s for the locked CDN URL. It also reports the old APK's 404 from `dl-4` and prior DNS failure for the Alpine archive host. Those are useful corroborating historical/current metadata facts, not verification of the original APK bytes. This search adds a current 404 from TUNA and network failure/redirect details from the other endpoints.

**No package-license or redistribution review was performed.** No APK was downloaded or opened. Do not infer that the artifact is unrecoverable or redistributable from these probes.

## Content-addressed source check and next safe action

The locked files and reviewed RFC identify package URLs and digests but no trusted public content-addressed blob repository. The bounded source set therefore used the official/listed distro mirror endpoints and the Alpine archive host; no arbitrary hash-search service was queried. The Node.js copies match the pinned digest exactly. For Alpine, a follow-up may continue only with an identified, trusted archive/cache endpoint and the same HEAD-first, exact-size-capped GET plus digest verification. If no such source is known, preserve the existing lock and request a separately approved recovery or version-refresh plan; do not weaken or rewrite the sample pin based on these acquisition failures.

## Commands and operations

- Resolved task context with `python3 ./.trellis/scripts/task.py current --source`; it reported no current task pointer. The explicit task path in the request was used for the single requested output file.
- Used bounded `curl -I -L` HEAD probes before package GETs. Successful GETs used `curl -L --fail --max-filesize 10349280` and wrote only to `/tmp/pr29-exact-package-search-20261022-rzeejG/`.
- Verified both Node.js files using `wc -c` and `sha256sum`; both exactly match the locked length and SHA-256.
- Did not extract, unpack, run, install, repoint, or redistribute packages. No CI rerun, task-status change, commit, push, or merge was performed.
