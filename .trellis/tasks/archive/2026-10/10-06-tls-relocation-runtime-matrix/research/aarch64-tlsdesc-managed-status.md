# TLSDESC managed producer status

## Completed bounded producer slice

The exact TLSDESC semantic/layout contract now reaches the managed protection
producer. The producer admits only the four ordered static markers
`R_AARCH64_TLSDESC_ADR_PAGE21`, `R_AARCH64_TLSDESC_LD64_LO12`,
`R_AARCH64_TLSDESC_ADD_LO12`, and `R_AARCH64_TLSDESC_CALL`, one defined TLS
symbol/addend, one loader-owned dynamic descriptor, paired
`DT_TLSDESC_PLT/GOT` tags, and the exact six-word resolver stub.

`FunctionAnalysis` treats only the marker-owned `BLR X1` as a fallthrough
resolver call. The flattening emitter emits that BLR and keeps the following
block physically adjacent, so the eight source words remain contiguous for
`ElfLayoutPlanner` and `ElfLayoutMaterializer`. Ordinary indirect branches
remain rejected.

The semantic projector, fixup encoder, plan validator, rehydration gate, and
materializer now recognize the TLSDESC page/LD64/ADD marker family. Materializer
validation reparses the full descriptor range, dynamic relocation, resolver
PLT/GOT ranges and permissions, output word sequence, and PT_TLS facts before
publication.

## Evidence

- `tests/UrProtect.Core.Tests/Structural/TlsDescriptorElfFixture.cs` provides a
  bounded synthetic ET_DYN fixture with initialized TLS, zero-fill, one
  16-byte descriptor, paired dynamic tags, and the resolver stub.
- `TlsLocalExecWorkflowTests.SelectedTlsDescFunctionFlowsThroughSnapshotSharedLayoutAndReparse`
  proves parser/owner projection, exact word recognition, producer success,
  typed snapshot binding, four fixups, and one Protected Image snapshot
  operation.
- The independent GNU fixture in `aarch64-tlsdesc-oracle.md`, linked with
  retained static relocations (`--emit-relocs`), reaches the same producer path
  and `urprotect protect` exits 0 with an output artifact.
- Release managed tests pass with 374 tests. The native launcher override
  `make -C native/urprotect-launcher test CC=aarch64-linux-gnu-gcc` passes.

## Remaining boundary

The slice is managed semantic/layout evidence only. No transformed TLSDESC
runtime row is promoted for glibc, musl, or bionic. Relaxed TLSDESC relocation
forms, dynamic lifecycle evidence, worker teardown, and native runtime support
remain separate follow-up work.
