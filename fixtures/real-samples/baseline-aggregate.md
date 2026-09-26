# Public real-sample aggregate (pr)

Distinct project identities: **20/100** (shortfall: **80**).
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

## Feature frequency

| Feature | Identities | Percent | Disposition |
| --- | ---: | ---: | --- |
| `elf.class.ELF64` | 20 | 100.00% | `deferred` |
| `elf.data.little-endian` | 20 | 100.00% | `deferred` |
| `elf.machine.AArch64` | 20 | 100.00% | `deferred` |
| `elf.type.ET_DYN` | 18 | 90.00% | `deferred` |
| `elf.type.ET_EXEC` | 2 | 10.00% | `deferred` |
| `loader./lib/ld-linux-aarch64.so.1` | 18 | 90.00% | `deferred` |
| `loader./lib/ld-musl-aarch64.so.1` | 1 | 5.00% | `deferred` |
| `loader./system/bin/linker64` | 1 | 5.00% | `deferred` |

## Runtime, loader, producer, and page-size coverage

### Runtime

| Value | Identities |
| --- | ---: |
| `bionic` | 1 |
| `glibc` | 18 |
| `musl` | 1 |

### Loader

| Value | Identities |
| --- | ---: |
| `/lib/ld-linux-aarch64.so.1` | 18 |
| `/lib/ld-musl-aarch64.so.1` | 1 |
| `/system/bin/linker64` | 1 |

### Producer

| Value | Identities |
| --- | ---: |
| `alpine-musl-gcc` | 1 |
| `autotools-gcc` | 11 |
| `cmake-gcc` | 1 |
| `configure-gcc` | 2 |
| `go` | 1 |
| `make-gcc` | 2 |
| `rustc` | 1 |
| `termux-clang` | 1 |

### Page size

| Value | Identities |
| --- | ---: |
| `4096` | 20 |

## Unexpected outcomes

- None recorded in the aggregate input.

Registry-only baseline facts are labeled metadata; they do not promote product support.
Per-sample evidence is linked by `projectId`; raw archives and binaries are never retained here.
