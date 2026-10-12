# AArch64 TLSDESC Oracle

## Scope and status

This is a bounded GNU assembler/linker oracle for one AArch64 TLSDESC shape. It
is ABI, structural, and semantic/layout evidence only. It does not prove a
transformed image, a native loader/runtime row, worker lifecycle, teardown,
unload, rollback, glibc, musl, or bionic support.

The source fixture is:

- `research/aarch64-tlsdesc-fixture.s`

It has one selected function, one initialized TLS object (`tls_desc_value`),
and one separate `.tbss` object (`tls_desc_zero`) that forces PT_TLS zero-fill.
The selected function reads only the initialized object; the zero-fill object is
a structural PT_TLS witness so that this exact TLSDESC slice carries both
`p_filesz` and `p_memsz - p_filesz` facts without adding a second descriptor
sequence.

## Toolchain and reproduction

Toolchain identity in this workspace:

```text
aarch64-linux-gnu-gcc       Ubuntu 15.2.0-16ubuntu1
aarch64-linux-gnu-as        GNU binutils 2.46
aarch64-linux-gnu-ld.bfd    GNU binutils 2.46
aarch64-linux-gnu-readelf   GNU binutils 2.46
aarch64-linux-gnu-objdump   GNU binutils 2.46
packages: gcc-15-aarch64-gnu 15.2.0-16ubuntu1, binutils-aarch64-linux-gnu 2.46-3ubuntu2
```

Commands used:

```sh
rm -rf /tmp/urprotect-tlsdesc-oracle
mkdir -p /tmp/urprotect-tlsdesc-oracle

aarch64-linux-gnu-as --noexecstack \
  -o /tmp/urprotect-tlsdesc-oracle/tlsdesc.o \
  .trellis/tasks/10-06-tls-relocation-runtime-matrix/research/aarch64-tlsdesc-fixture.s

aarch64-linux-gnu-ld.bfd -shared --no-relax \
  -o /tmp/urprotect-tlsdesc-oracle/tlsdesc.so \
  /tmp/urprotect-tlsdesc-oracle/tlsdesc.o

aarch64-linux-gnu-readelf -hW -lW -SW -dW -rW -sW \
  /tmp/urprotect-tlsdesc-oracle/tlsdesc.o

aarch64-linux-gnu-objdump -drwC \
  /tmp/urprotect-tlsdesc-oracle/tlsdesc.o

aarch64-linux-gnu-readelf -hW -lW -SW -dW -rW -sW \
  /tmp/urprotect-tlsdesc-oracle/tlsdesc.so

aarch64-linux-gnu-objdump -drwC -s -j .plt -j .text -j .tdata -j .tbss \
  -j .got -j .got.plt /tmp/urprotect-tlsdesc-oracle/tlsdesc.so
```

`--no-relax` was selected so that the four static TLSDESC markers remain an
explicit source contract. The default `aarch64-linux-gnu-ld.bfd -shared` link
produced the same linked-image SHA-256 for this fixture, but relaxed forms are
still outside this bounded slice.

Artifact identity from this run:

```text
9f42a60463d82d37051329ada582c07fdd9641a66a9583759989fc7ad957fad8  aarch64-tlsdesc-fixture.s
6651d3115f1d175260cb59d0e9a51a2a0dc2a9ffdac6f7fcfd28c87514bb1b7b  tlsdesc.o (1352 bytes)
8c4fbbc6fc8d8f52389c3c101bbcbfd51bb21d2269bf02fa907ce76cca815fe6  tlsdesc.so (67304 bytes)
```

The numeric names were cross-checked against `/usr/include/elf.h` and
`/usr/include/llvm-21/llvm/BinaryFormat/ELFRelocs/AArch64.def`.

## Exact source instruction sequence

The fixture source is:

```asm
.text
.align 2
tlsdesc_entry:
    adrp x0, :tlsdesc:tls_desc_value
    ldr x1, [x0, #:tlsdesc_lo12:tls_desc_value]
    add x0, x0, :tlsdesc_lo12:tls_desc_value
    .tlsdesccall tls_desc_value
    blr x1
    mrs x1, tpidr_el0
    add x0, x1, x0
    ldr w0, [x0]
    ret
```

The relocatable `.text` section is 0x20 bytes. The exact contiguous resource
flow is:

| Offset | Encoding | Instruction | Resource/semantic role |
|---|---:|---|---|
| 0x00 | `0x90000000` | `ADRP x0, :tlsdesc:` | Forms the descriptor page; `x0` owns the descriptor address. |
| 0x04 | `0xf9400001` | `LDR x1, [x0]` | Loads the descriptor's resolver/function word into `x1`; 64-bit load, scale 8, base `x0`. |
| 0x08 | `0x91000000` | `ADD x0, x0, #0` | Completes the descriptor address; `x0` remains the first resolver argument. |
| 0x0c | `0xd63f0020` | `BLR x1` | Indirect descriptor resolver call. The marker is `R_AARCH64_TLSDESC_CALL`; it is not `CALL26`. |
| 0x10 | `0xd53bd041` | `MRS x1, TPIDR_EL0` | Reads the thread pointer after the resolver call, reusing `x1`. |
| 0x14 | `0x8b000020` | `ADD x0, x1, x0` | Forms the final address as `TP + resolver-returned offset` in `x0`. |
| 0x18 | `0xb9400000` | `LDR w0, [x0]` | Final 4-byte TLS memory access; base must be the finalized `x0`. |
| 0x1c | `0xd65f03c0` | `RET` | Returns the loaded initialized TLS value. |

The resolver result is consumed in `x0`; the post-call `MRS` and register ADD
make the descriptor-mediated address expression explicit. The fixture has no
external `__tls_get_addr` reference and no ordinary direct resolver call. The
resolver path is linker/loader-provided TLSDESC machinery.

## Relocations in the relocatable object

`.rela.text` contains exactly four records, in source instruction order. All
four use symbol index 11 (`tls_desc_value`) and addend `0`:

| Offset | `r_info` | Type | Numeric | Symbol | Addend |
|---|---:|---|---:|---|---:|
| 0x0000 | `0x0000000b00000232` | `R_AARCH64_TLSDESC_ADR_PAGE21` | 562 / `0x232` | `tls_desc_value` | 0 |
| 0x0004 | `0x0000000b00000233` | `R_AARCH64_TLSDESC_LD64_LO12` | 563 / `0x233` | `tls_desc_value` | 0 |
| 0x0008 | `0x0000000b00000234` | `R_AARCH64_TLSDESC_ADD_LO12` | 564 / `0x234` | `tls_desc_value` | 0 |
| 0x000c | `0x0000000b00000239` | `R_AARCH64_TLSDESC_CALL` | 569 / `0x239` | `tls_desc_value` | 0 |

`R_AARCH64_TLSDESC_CALL` is the ABI/linker marker attached to the `BLR x1`
word. There is no `R_AARCH64_CALL26` in the object and no `__tls_get_addr`
relationship. The source sequence is therefore the exact four-site pattern:

```text
TLSDESC_ADR_PAGE21
TLSDESC_LD64_LO12
TLSDESC_ADD_LO12
TLSDESC_CALL
```

The other ABI-defined TLSDESC instruction relocations are not present in this
positive object: `TLSDESC_LD_PREL19`, `TLSDESC_ADR_PREL21`,
`TLSDESC_OFF_G1`, `TLSDESC_OFF_G0_NC`, `TLSDESC_LDR`, and `TLSDESC_ADD`.

## Linked image shape

The `--no-relax` shared object is `ET_DYN`, AArch64, with the selected function
at `0x2b0` and size `0x20`:

```text
0x2b0  90000100  adrp x0, 0x20000
0x2b4  f9400001  ldr  x1, [x0, #0]
0x2b8  91000000  add  x0, x0, #0
0x2bc  d63f0020  blr  x1
0x2c0  d53bd041  mrs  x1, tpidr_el0
0x2c4  8b000020  add  x0, x1, x0
0x2c8  b9400000  ldr  w0, [x0]
0x2cc  d65f03c0  ret
```

The page target is descriptor page `0x20000`; both observed low-12 values are
zero because this linker placed the descriptor at the start of that page. The
positive fixture therefore proves the page/scale/register shape, while a future
nonzero-low-12 fixture is still needed before broad low-12 relaxation claims.

The linked sections needed by the slice are:

```text
.rela.plt  VA 0x0250  file 0x0250  size 0x18  one RELA record
.plt       VA 0x0270  file 0x0270  size 0x40  AX
.text      VA 0x02b0  file 0x02b0  size 0x20  AX
.tdata     VA 0x1fec0 file 0xfec0  size 0x04  WAT
.tbss      VA 0x1fec8 file 0xfec8  size 0x10  WAT, NOBITS
.dynamic   VA 0x1fec8 file 0xfec8  size 0x110 WA
.got       VA 0x1ffd8 file 0xffd8  size 0x10  WA
.got.plt   VA 0x1ffe8 file 0xffe8  size 0x28  WA
```

### PT_TLS geometry

```text
PT_TLS:  file offset 0x00fec0, VA 0x000000000001fec0
         p_filesz 0x04, p_memsz 0x18, p_align 0x08, flags R
owner:   PT_LOAD[1], file/VA start 0x00fec0 / 0x1fec0
         p_filesz 0x150, p_memsz 0x150, flags RW, p_align 0x10000
```

The initialized template is `44 33 22 11` (`0x11223344`). The zero-fill is
`0x14` bytes: four bytes of alignment padding after `.tdata`, followed by the
16-byte `.tbss` object at TLS value `0x8`. The linked symbols are:

```text
tls_desc_value  STT_TLS, value 0x0, size 0x4, section .tdata
tls_desc_zero   STT_TLS, value 0x8, size 0x10, section .tbss
_TLS_MODULE_BASE_ STT_TLS, value 0x0, local linker symbol
tlsdesc_entry   FUNC, value 0x2b0, size 0x20
```

The PT_TLS segment is read-only (`R`) even though its owning load is RW, which
matches the StructuralElf permission contract: PT_TLS must be readable, must
not be executable, and may require write coverage from its owning PT_LOAD.

### Descriptor, GOT, and dynamic tags

The per-symbol descriptor is the 16-byte range `[0x20000, 0x20010)` in the
writable `.got.plt` section. The linked file contains zero placeholders there;
the dynamic loader owns the descriptor contents. One dynamic relocation targets
the first descriptor word:

```text
.rela.plt file offset 0x250, size 0x18
r_offset  0x0000000000020000
r_info    0x0000000200000407
type      R_AARCH64_TLSDESC (1031 / 0x407)
symbol    dynsym index 2, tls_desc_value (STT_TLS)
addend    0
```

No second ELF relocation is emitted for the descriptor's second 8-byte word.
The static fact needed for layout is therefore a 16-byte descriptor range with a
loader-owned `R_AARCH64_TLSDESC` identity at its first word. The existing
StructuralElf relocation width for `R_AARCH64_TLSDESC` is 8 bytes; the full
16-byte descriptor extent must not be lost when validating or preserving the
layout.

The dynamic tags are present as a pair:

```text
DT_TLSDESC_PLT  (0x6ffffef6) = 0x290
DT_TLSDESC_GOT  (0x6ffffef7) = 0x1ffe0
DT_PLTGOT       (3)          = 0x1ffe8
```

`DT_TLSDESC_GOT` is not the per-symbol descriptor address. It points at the
second 8-byte slot of `.got` (`[0x1ffe0, 0x1ffe8)`), used by the special
TLSDESC resolver PLT entry. The special linker-created stub at `0x290` is:

```text
0x290  a9bf0fe2  stp  x2, x3, [sp, #-16]!
0x294  f00000e2  adrp x2, 0x1f000
0x298  f00000e3  adrp x3, 0x1f000
0x29c  f947f042  ldr  x2, [x2, #0xfe0]   // resolver word at 0x1ffe0
0x2a0  913fa063  add  x3, x3, #0xfe8     // PLTGOT base 0x1ffe8
0x2a4  d61f0040  br   x2
```

The descriptor range starts at the end of GNU_RELRO (`GNU_RELRO` VA
`0x1fec0`, size `0x140`, end `0x20000`), while the `DT_TLSDESC_GOT` resolver
slot at `0x1ffe0` is within RELRO. This is a useful preservation invariant for
lazy/immediate loader ownership. The static linked image has no applied runtime
resolver contents to compare; the `.got`/`.got.plt` dump shows zero placeholder
words except the ordinary `_DYNAMIC` pointer at `0x1ffd8`.

## Repository boundary alignment

The current constants and parser already cover the ABI names and values:

- `src/UrProtect.Core/StructuralElf/ElfTypes.cs:86-87` declares
  `DT_TLSDESC_PLT/GOT`; `:167-184` declares the instruction and dynamic
  TLSDESC relocation constants; `:495-499` classifies them as
  `Aarch64RelocationKind.ThreadLocal`.
- `src/UrProtect.Core/StructuralElf/ElfTlsParser.cs:33-53` parses the dynamic
  tags and rejects a one-tag-only image.
- `ElfTlsParser.cs:847-864` gives static TLSDESC instruction relocations a
  4-byte write width and `R_AARCH64_TLSDESC` an 8-byte relocation width. It
  does not carry a separate 16-byte descriptor extent.
- `src/UrProtect.Core/StructuralElf/TlsFacts.cs` carries PT_TLS and dynamic
  relocation facts plus the two dynamic tag addresses, but has no typed
  per-descriptor owner record.
- `src/UrProtect.Core/SemanticPlanning/TlsSemanticModels.cs:300-395` maps the
  TLSDESC range to `TlsRelocationFamily.TlsDesc` and `TlsAccessModel.TlsDesc`.
  `IsCompleteRelocationPattern` currently checks only set membership of the
  four positive instruction types; it does not enforce order, adjacency,
  addends, register ownership, or the dynamic `R_AARCH64_TLSDESC` owner.
- `Aarch64TlsSequenceRecognizer.cs:594-602` recognizes a broad ADRP/LDR/ADD/
  BLR/post-call-ADD/memory shape. `:921-939` treats any `BLR` or direct-call
  instruction as the TLSDESC resolver and accepts the synthetic runtime target
  string `tlsdesc:resolver`; it does not bind the observed
  `R_AARCH64_TLSDESC_CALL` marker or the linker-created TLSDESC PLT/GOT pair.
- `TlsStructuralAdapter.cs:329-397` projects only the
  `__tls_get_addr`/JUMP_SLOT/CALL26 resolver relationship. It can project a
  TLSDESC relocation site (`:570-617`) but has no unique TLSDESC descriptor
  owner/tag projection. `R_AARCH64_TLSDESC_CALL` also classifies generically as
  `ThreadLocal`, not as `Call26`.
- Snapshot validation already requires `TlsResolverKind.TlsDesc` and the
  `DescriptorLoad`, `DescriptorCall`, and `AddressFinalization` roles, but its
  model-specific relocation check still relies on the unordered classifier
  contract.

## Smallest exact semantic/layout slice

The smallest positive vertical slice supported by this oracle is one linked
image-local TLSDESC access with this exact contract:

1. One contiguous decoded function sequence with `ADRP X0`, 64-bit `LDR X1`
   from `[X0]`, `ADD X0,X0,#imm12`, `BLR X1`, `MRS X1,TPIDR_EL0`,
   `ADD X0,X1,X0`, and one final scalar TLS access based on `X0`.
2. Four adjacent instruction relocations, pair ordinals 0 through 3, in the
   exact order `ADR_PAGE21`, `LD64_LO12`, `ADD_LO12`, `CALL`, all for the same
   defined `STT_TLS` symbol and the same addend. The positive evidence has
   addend zero and descriptor low-12 zero; nonzero addends/low-12 values need
   separate fixture evidence before support is widened.
3. One linked dynamic `R_AARCH64_TLSDESC` owner for the same TLS symbol and
   addend, with its relocation target in a unique writable, file-backed mapped
   range. Validate and preserve the complete 16-byte descriptor range even
   though the ELF relocation record's `r_offset`/StructuralElf write width is
   8 bytes.
4. A paired, valid `DT_TLSDESC_PLT` executable address and `DT_TLSDESC_GOT`
   writable address. Preserve both tags, the special resolver PLT shape, the
   resolver GOT slot, the descriptor GOT range, and the dynamic relocation
   table. Do not substitute `CALL26`, `JUMP_SLOT __tls_get_addr`, or a guessed
   resolver symbol.
5. A descriptor-mediated address expression: the descriptor call returns an
   offset in `X0`, then `TPIDR_EL0 + X0` forms the final address. Register
   liveness and aliasing must be checked on reparse, not inferred from mnemonic
   order alone.
6. Output placement and instruction fields are calculated by UrProtect's ELF/
   TLS semantic/layout owners, while final AArch64 words are encoded through
   the AsmStone-backed project encoder. Preserve the `TLSDESC_CALL` marker on
   the indirect call; it is not a PC-relative `BL` fixup.
7. PT_TLS `p_offset`, `p_vaddr`, `p_filesz`, `p_memsz`, alignment, permissions,
   initialized template bytes, zero-fill size, owning load, dynamic tags,
   descriptor/GOT ranges, and loader-owned relocation identity must remain
   equivalent after materialization and reparse. No runtime row is promoted by
   this static evidence.

## Nearest malformed and unsupported cases

These should fail closed before artifact or image publication:

- Missing, duplicate, reversed, non-adjacent, interleaved, or differently
  symbol-bound TLSDESC instruction sites; inconsistent addends or pair ordinals.
- `ADR_PREL21`, `LD_PREL19`, MOVW/offset, `TLSDESC_LDR`, or `TLSDESC_ADD`
  forms reaching the page/LD64/ADD slice; those are separate ABI shapes.
- A non-ADRP at the `ADR_PAGE21` site, a non-64-bit or wrong-scale LDR at the
  `LD64_LO12` site, a wrong base/destination register, an ADD that does not
  preserve the descriptor address, or a `BL`/direct call in place of `BLR X1`.
- Missing TP read, wrong TP register, resolver result overwritten before the
  final ADD, final memory access based on another register, unsupported access
  width, or a second resolver call.
- Missing or duplicated `R_AARCH64_TLSDESC`, wrong symbol/addend, target not
  writable/file-backed, descriptor range truncated below 16 bytes, or target
  outside the owning RW PT_LOAD.
- Missing only one of `DT_TLSDESC_PLT` and `DT_TLSDESC_GOT`, a tag with the
  wrong permission mapping, a changed resolver GOT/PLT relationship, or a
  dynamic relocation table that no longer owns the descriptor record.
- `R_AARCH64_CALL26`, `R_AARCH64_JUMP_SLOT __tls_get_addr`, local/initial-exec
  reinterpretation, unresolved/bounded resolver identity, or any conversion
  from descriptor-mediated semantics to a guessed static TLS slot.
- Relaxed output whose source marker identity is no longer recoverable, and
  any TLS descriptor form not independently covered by a linker oracle.

## Runtime-evidence boundary and limitations

The assembler and linker establish only the static facts above. No transformed
image was produced or executed. No glibc, musl, or bionic row is claimed; no
constructor/destructor, worker-thread, unload, release-order, or rollback
witness exists for this oracle.

The workspace has the AArch64 cross assembler/linker/readelf/objdump and GCC,
but no `qemu-aarch64` and no AArch64 cross dynamic loader at the checked paths.
`adb devices` reported no attached device. Therefore this pass cannot establish
native loader behavior, lazy versus immediate descriptor binding, or per-thread
initialized/zero-fill observations. Those remain separate runtime-matrix work
items after the semantic/layout gate.
