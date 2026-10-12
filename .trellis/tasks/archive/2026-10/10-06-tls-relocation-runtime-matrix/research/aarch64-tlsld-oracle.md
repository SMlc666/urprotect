# AArch64 TLSLD module-base and DTPREL oracle

## Scope

This artifact records the exact linker-produced local-dynamic (TLSLD) shape used to define the next managed semantic slice. It is ABI, structural, and semantic/layout evidence only. It is not runtime support evidence for glibc, musl, bionic, worker lifecycle, unload, or transformed-image execution.

The checked-in source fixture is:

```text
.trellis/tasks/10-06-tls-relocation-runtime-matrix/research/aarch64-tlsld-fixture.s
```

The fixture contains one selected function, initialized TLS (`tls_ld_value`), TLS zero-fill (`tls_ld_zero`), and an external `__tls_get_addr` resolver:

```asm
.text
.align 2
tlsld_entry:
    adrp x0, :tlsldm:tls_ld_value
    add x0, x0, :tlsldm_lo12_nc:tls_ld_value
    bl __tls_get_addr
    add x0, x0, #:dtprel_hi12:tls_ld_value+4, lsl #12
    add x0, x0, #:dtprel_lo12_nc:tls_ld_value+4
    ldr w0, [x0]
    ret
```

## Toolchain evidence

The pinned local cross-toolchain reported:

```text
GCC 15.2.0
GNU assembler 2.46
GNU ld.bfd 2.46
GNU readelf 2.46
GNU objdump 2.46
```

The fixture was assembled and linked with:

```sh
aarch64-linux-gnu-as -o /tmp/urprotect-tlsld-oracle/tlsld.o \
  .trellis/tasks/10-06-tls-relocation-runtime-matrix/research/aarch64-tlsld-fixture.s
aarch64-linux-gnu-ld.bfd -shared \
  -o /tmp/urprotect-tlsld-oracle/tlsld.so \
  /tmp/urprotect-tlsld-oracle/tlsld.o
aarch64-linux-gnu-readelf -hW -lW -SW -rW -sW /tmp/urprotect-tlsld-oracle/tlsld.o
aarch64-linux-gnu-objdump -drwC /tmp/urprotect-tlsld-oracle/tlsld.o
aarch64-linux-gnu-readelf -hW -lW -SW -rW -sW /tmp/urprotect-tlsld-oracle/tlsld.so
aarch64-linux-gnu-objdump -drwC /tmp/urprotect-tlsld-oracle/tlsld.so
```

Observed SHA-256 values for this toolchain run:

```text
904a166d9c290fce9efcb5b39640a8a4947ccd5952cf6678328e53628eae810a  tlsld.o
b9193a933a224cf55991c19bb229710cc91d528edcdbdd19c861e7c15b2aef95  tlsld.so
```

The project constants agree with `/usr/include/elf.h` and the AArch64 relocation declarations:

```text
R_AARCH64_TLSLD_ADR_PREL21       517 / 0x205
R_AARCH64_TLSLD_ADR_PAGE21       518 / 0x206
R_AARCH64_TLSLD_ADD_LO12_NC      519 / 0x207
R_AARCH64_TLSLD_MOVW_G1          520 / 0x208
R_AARCH64_TLSLD_MOVW_G0_NC       521 / 0x209
R_AARCH64_TLSLD_LD_PREL19        522 / 0x20a
R_AARCH64_TLSLD_MOVW_DTPREL_G2   523 / 0x20b
R_AARCH64_TLSLD_MOVW_DTPREL_G1   524 / 0x20c
R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC 525 / 0x20d
R_AARCH64_TLSLD_MOVW_DTPREL_G0   526 / 0x20e
R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC 527 / 0x20f
R_AARCH64_TLSLD_ADD_DTPREL_HI12  528 / 0x210
R_AARCH64_TLSLD_ADD_DTPREL_LO12  529 / 0x211
R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC 530 / 0x212
R_AARCH64_TLSLD_LDST32_DTPREL_LO12 535 / 0x217
R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC 536 / 0x218
R_AARCH64_TLS_DTPMOD64           1028 / 0x404
R_AARCH64_TLS_DTPREL64           1029 / 0x405
```

The first implementation boundary uses only the exact five-site object sequence observed below:

```text
TLSLD_ADR_PAGE21
TLSLD_ADD_LO12_NC
CALL26 __tls_get_addr
TLSLD_ADD_DTPREL_HI12
TLSLD_ADD_DTPREL_LO12_NC
```

The other TLSLD instruction families remain explicit nearest-negative cases until their exact instruction/resource/layout contracts are implemented.

## Relocatable object facts

The `.rela.text` table contains exactly five records, in instruction order, all with the local TLS symbol identity and the shown addends:

```text
offset  type                              symbol         addend
0x0000  R_AARCH64_TLSLD_ADR_PAGE21       tls_ld_value   0
0x0004  R_AARCH64_TLSLD_ADD_LO12_NC      tls_ld_value   0
0x0008  R_AARCH64_CALL26                 __tls_get_addr 0
0x000c  R_AARCH64_TLSLD_ADD_DTPREL_HI12  tls_ld_value   4
0x0010  R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC tls_ld_value  4
```

The source symbol is `STT_TLS`, hidden, defined at TLS value `0x4`, with size `0x4`. The fixture also defines `tls_ld_zero` as a hidden TLS object in `.tbss`, value `0x8`, size `0x10`. `_TLS_MODULE_BASE_` is the local linker TLS module-base symbol at value zero.

The object instruction sequence is contiguous and has the exact ownership split:

```text
0x0000  ADRP x0, module-id/GOT TLSLD target
0x0004  ADD  x0, x0, module-id/GOT low 12 bits
0x0008  BL   __tls_get_addr
0x000c  ADD  x0, x0, DTPREL high 12 bits
0x0010  ADD  x0, x0, DTPREL low 12 bits
0x0014  LDR  w0, [x0]
0x0018  RET
```

The `BL` is a real direct call and is part of the TLSLD sequence, not a generic call that may be silently copied by the current function emitter.

## Linked image facts

The linked shared object contains:

```text
.text    VA 0x0000000000000290, file offset 0x0290, size 0x1c
.tdata   VA 0x000000000001fea8, file offset 0xfea8, size 0x8
.tbss    VA 0x000000000001feb0, file offset 0xfeb0, size 0x10
.got     VA 0x000000000001ffd0, file offset 0xffd0, size 0x18, WA
```

Its PT_TLS is:

```text
offset 0x00fea8
virtual address 0x000000000001fea8
file size 0x8
memory size 0x18
flags R
alignment 0x8
```

Thus the initialized template is eight bytes (`0xddccbbaa44332211` in the linked section dump), and the remaining sixteen bytes are loader-provided zero-fill. The owning RW PT_LOAD begins at file/virtual offset `0x00fea8`, has file/memory size `0x160`, and alignment `0x10000`. The image also contains a GNU_RELRO range covering the TLS/dynamic/GOT region.

The linked code is:

```text
0x290  f00000e0  adrp x0, 0x1f000
0x294  913f6000  add  x0, x0, #0xfd8
0x298  97fffffa  bl   __tls_get_addr@plt
0x29c  91400000  add  x0, x0, #0x0, lsl #12
0x2a0  91002000  add  x0, x0, #0x8
0x2a4  b9400000  ldr  w0, [x0]
0x2a8  d65f03c0  ret
```

The `.got` bytes are:

```text
VA 0x1ffd0: b0fe0100 00000000 00000000 00000000
VA 0x1ffe0: 00000000 00000000
```

The linked dynamic relocation table retains the loader-owned module identity relocation at GOT address `0x1ffd8`:

```text
0x0001ffd8  R_AARCH64_TLS_DTPMOD64  addend 0
```

The linked PLT relocation table contains the resolver binding:

```text
0x00020000  R_AARCH64_JUMP_SLOT  __tls_get_addr  addend 0
```

The linked symbol table retains `tls_ld_value` as a local TLS symbol at value `0x4`, `tls_ld_zero` at value `0x8` with size `0x10`, `_TLS_MODULE_BASE_` at value zero, and `tlsld_entry` at `0x290` with size `0x1c`.

The linker-created module-ID slot is therefore a distinct loader-owned object from the DTPREL symbol offset. The TLSLD ADRP/ADD pair forms the address of that slot, `__tls_get_addr` consumes the module-ID and zero symbol offset tuple, and the post-call DTPREL pair adds the local symbol offset to the returned module base.

## Semantic contract

The first local-dynamic slice must carry one typed binding containing:

- `TlsAccessModel.LocalDynamic`;
- primary `TlsRelocationFamily.Dtpmod` plus the paired `Dtprel` sites;
- image-local module identity and the exact PT_TLS template/zero-fill contract;
- `tls_ld_value` symbol identity, value, size, visibility, and addend;
- the contiguous ADRP/ADD, direct resolver call, DTPREL ADD/ADD, and final access sequence;
- resolver kind `TlsResolverKind.TlsGetAddr` with a resolved `__tls_get_addr` target;
- module-relative address expression with the returned module-base register and final value register;
- source relocation identity for all five instruction sites, including `CALL26`, plus the dynamic `R_AARCH64_TLS_DTPMOD64` owner and its GOT range;
- profile and runtime requirements without promoting any runtime row.

The DTPMOD owner must remain loader-owned. The rewriter may relocate the selected code and recompute instruction encodings, but it must preserve the dynamic relocation record, its target range, symbol/module meaning, and the GOT bytes/permissions. It must not convert local-dynamic into initial-exec or replace the resolver call with a guessed static slot.

The DTPREL high/low pair is a module-relative symbol-offset formation after `__tls_get_addr`. The pair has the same symbol identity and addend (`4` in this fixture), is ordered and adjacent, and must preserve register ownership: the resolver result in `x0` is consumed as the base and the DTPREL ADD chain must produce the base used by the final TLS memory access.

## Current implementation boundary

The existing repository already has typed model vocabulary and structural parsing for local-dynamic:

- `TlsAccessModel.LocalDynamic` and `TlsRelocationFamily.Dtpmod`/`Dtprel` exist;
- `ElfConstants` contains the TLSLD and dynamic TLS relocation values;
- `ElfTlsParser` parses PT_TLS, dynamic TLS relocation tables, and bounded symbol facts;
- `Aarch64TlsSequenceRecognizer` requires a resolver call for local-dynamic and classifies its expression as module-relative;
- snapshot validation requires a TLS-get-addr resolver and both DTPMOD and DTPREL families.

The current selected-function and physical publication path is intentionally narrower:

- `FunctionProtectionPlanning` accepts only local-exec and exact initial-exec slices;
- `FunctionProtectionCodeEmitter` rejects generic direct calls and unrelated PC-relative instructions, with only the initial-exec PC-relative load exceptions admitted;
- `ElfLayoutPlanner` validates and applies only local-exec and initial-exec fixups;
- `ElfLayoutMaterializer` validates only the existing local-exec and initial-exec output contracts;
- `GenericRehydrationEngine` and producer-side snapshot binding validation reject transformed bindings outside those two models.

The first local-dynamic implementation must therefore extend the selected-function emitter, semantic planning, shared layout planner/materializer, and rehydration publication validation together. Adding recognizer-only support or accepting the direct `BL` through the generic call bypass would leave an incomplete artifact and weaken the existing safety boundary.

## Exact first slice

The recommended first bounded vertical slice is:

1. recognize exactly the five-site TLSLD object sequence above;
2. admit only the `BL __tls_get_addr` instruction when its semantic resolver target is exact and its call range is re-encoded through the existing semantic call fixup path;
3. support only adjacent `TLSLD_ADR_PAGE21 + TLSLD_ADD_LO12_NC` module-ID formation;
4. support only adjacent `TLSLD_ADD_DTPREL_HI12 + TLSLD_ADD_DTPREL_LO12_NC` symbol-offset formation;
5. preserve the dynamic `R_AARCH64_TLS_DTPMOD64` GOT owner and PT_TLS metadata byte-for-byte/structurally;
6. carry all five instruction relocations and the loader-owned dynamic relocation through the canonical snapshot and layout evidence;
7. validate source/output page range, low-12 fields, addends, register ownership, resolver identity, GOT ownership, output mapping, and final memory access on reparse;
8. publish no Native Image if any sequence, resolver, dynamic relocation, output range, or metadata invariant fails.

No TLSLD MOVW, TLSLD literal-load, TLSLD LD/ST offset forms, TLSGD/general-dynamic, or TLSDESC form is included in this slice. Those forms remain explicit unsupported diagnostics until separately evidenced and implemented.

## Nearest negative cases

The following must fail closed with stable semantic/layout diagnostics before artifact or Native Image publication:

- missing or duplicated DTPMOD owner;
- DTPMOD owner outside a writable mapped GOT or with the wrong dynamic relocation type;
- missing DTPREL pair, reversed pair, interleaved pair, wrong addend, or mismatched symbol identity;
- missing resolver call, wrong call target, indirect resolver call, or a generic direct call not owned by the recognized TLSLD sequence;
- ADRP/ADD page or low-12 range/placement mismatch;
- DTPREL high/low immediate, alignment, addend, or register mismatch;
- final TLS memory access using a register other than the DTPREL result;
- source/output address-map conflict or output range outside executable PT_LOAD;
- changed PT_TLS count, template, zero-fill, alignment, permissions, owning load, dynamic relocation table, GOT bytes, or relocation ownership;
- TLSGD, TLSIE, TLSDESC, TLSLD MOVW, TLSLD literal-load, and unrecognized relative/table-driven forms reaching this slice;
- any resolver or loader-owned target that is only bounded/unresolved rather than exactly identified.

## Runtime-evidence boundary

This oracle proves only:

- assembler acceptance of the exact TLSLD sequence;
- object relocation ordering and identity;
- linked PT_TLS geometry and initialized/zero-fill facts;
- linker-created module-ID GOT ownership and retained `R_AARCH64_TLS_DTPMOD64` metadata;
- linked `__tls_get_addr` PLT call shape;
- DTPREL symbol-offset encoding shape.

It does not prove transformed execution, current-thread behavior, registered-worker behavior, teardown ordering, glibc behavior, musl behavior, bionic behavior, or Ubuntu 24.04 matrix coverage. Each of those remains a separate evidence row after the complete managed semantic/layout gate passes.
