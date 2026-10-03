# Public real-sample aggregate (pr)

Distinct project identities: **100/100** (shortfall: **0**).
Evidence mode: `registry-baseline`; report schema: `2`.

## First-failure layers

| Layer | Identity count |
| --- | ---: |
| `acquisition` | 0 |
| `fingerprint` | 0 |
| `parse-model` | 0 |
| `static-validation` | 0 |
| `outer` | 0 |
| `host-context` | 0 |
| `environment` | 0 |

## Runtime layer outcomes

| Project | Runtime | Layer | Result |
| --- | --- | --- | --- |
| `busybox` | `musl` | `baseline` | `accepted-and-runs` |
| `busybox` | `musl` | `outerWrapper` | `accepted-and-runs` |
| `gnu-coreutils` | `glibc` | `baseline` | `accepted-and-runs` |
| `gnu-coreutils` | `glibc` | `outerWrapper` | `accepted-and-runs` |
| `nodejs` | `bionic` | `baseline` | `environment-unavailable` |
| `nodejs` | `bionic` | `outerWrapper` | `environment-unavailable` |

## Feature frequency

| Feature | Identities | Percent | Disposition |
| --- | ---: | ---: | --- |
| `elf.class.ELF64` | 100 | 100.00% | `deferred` |
| `elf.data.little-endian` | 100 | 100.00% | `deferred` |
| `elf.machine.AArch64` | 100 | 100.00% | `deferred` |
| `elf.type.ET_DYN` | 96 | 96.00% | `deferred` |
| `elf.type.ET_EXEC` | 4 | 4.00% | `deferred` |
| `loader./lib/ld-linux-aarch64.so.1` | 78 | 78.00% | `deferred` |
| `loader./lib/ld-musl-aarch64.so.1` | 21 | 21.00% | `deferred` |
| `loader./system/bin/linker64` | 1 | 1.00% | `deferred` |

## Runtime, loader, producer, and page-size coverage

### Runtime

| Value | Identities |
| --- | ---: |
| `bionic` | 1 |
| `glibc` | 78 |
| `musl` | 21 |

### Loader

| Value | Identities |
| --- | ---: |
| `/lib/ld-linux-aarch64.so.1` | 78 |
| `/lib/ld-musl-aarch64.so.1` | 21 |
| `/system/bin/linker64` | 1 |

### Producer

| Value | Identities |
| --- | ---: |
| `alpine-musl-g++` | 4 |
| `alpine-musl-gcc` | 17 |
| `autotools-gcc` | 24 |
| `cmake-gcc` | 1 |
| `configure-gcc` | 10 |
| `debian-bookworm-g++` | 3 |
| `debian-bookworm-gcc` | 32 |
| `go` | 3 |
| `make-gcc` | 4 |
| `rustc` | 1 |
| `termux-clang` | 1 |

### Page size

| Value | Identities |
| --- | ---: |
| `4096` | 100 |

## Unexpected outcomes

- None recorded in the aggregate input.

Registry-only baseline facts are labeled metadata; they do not promote product support.
Per-sample evidence is linked by `projectId`; raw archives and binaries are never retained here.
