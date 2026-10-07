# AArch64 TLSIE MOVW GOTTPREL G1/G0_NC oracle

## Verified bounded candidate

This slice supports only the ordered pair:

```text
R_AARCH64_TLSIE_MOVW_GOTTPREL_G1      539 / 0x21b
R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC   540 / 0x21c
```

The constants agree with `/usr/include/elf.h`, LLVM 21's
`ELFRelocs/AArch64.def`, and the project's `ElfConstants`.

## GNU assembler/linker observation

Observed toolchain on the implementation host:

```text
GCC 15.2.0
GNU assembler/readelf/objdump 2.46
```

The source used was:

```asm
.text
.global tls_fixture
.type tls_fixture, %function
.extern tls_value
.align 2
tls_fixture:
    movz x9, #:gottprel_g1:tls_value
    movk x9, #:gottprel_g0_nc:tls_value
    mrs x10, tpidr_el0
    add x9, x10, x9
    ldr x9, [x9]
    add x9, x10, x9
    ldr w0, [x9]
    ret
.size tls_fixture, .-tls_fixture
```

`aarch64-linux-gnu-gcc -c -fPIC` produced exactly two adjacent `.rela.text`
records, both with addend zero and symbol `tls_value`:

```text
Offset  Type
0x0000  R_AARCH64_TLSIE_MOVW_GOTTPREL_G1
0x0004  R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC
```

The relocatable instruction bytes were:

```text
0:  d2a00009  movz x9, #0, lsl #16
4:  f2800009  movk x9, #0
8:  d53bd04a  mrs  x10, tpidr_el0
c:  8b090149  add  x9, x10, x9
10: f9400129  ldr  x9, [x9]
14: 8b090149  add  x9, x10, x9
18: b9400120  ldr  w0, [x9]
1c: d65f03c0  ret
```

GNU shared linking with a defined `.tdata` `STT_TLS tls_value` consumed both
TLSIE MOVW records. The linked text contained `movz` plus `movk x9, #0x8,
lsl #0`, then the same TPIDR_EL0/GOT-load/final-address/TLS-access chain. The
linker retained one GOT entry relocation:

```text
Offset             Type
0x000000000001ffe0 R_AARCH64_TLS_TPREL64 tls_value + 0
```

The output had a writable `.got`/`.got.plt` load segment and a bounded `PT_TLS`
segment. The TLSIE pair therefore materializes the TP-relative address of the
GOT entry; the first 64-bit load reads the loader-written `R_AARCH64_TLS_TPREL64`
value, and the second TP-relative add forms the TLS object address.

## Recognition and ownership boundary

The managed recognizer requires all of the following:

- the exact ordered adjacent MOVZ/MOVN `hw=1` plus MOVK `hw=0` pair;
- 64-bit moves, one non-SP destination register, and one matching destination;
- one immediately following `MRS TPIDR_EL0`;
- one unshifted 64-bit `ADD` forming the GOT address;
- one 64-bit unsigned-immediate `LDR Xt, [Xgot]` with zero offset;
- one unshifted 64-bit `ADD` combining TP and the loaded GOT value;
- exactly one following TLS memory access using the resulting base;
- identical resolved symbol identity and addend on the pair; and
- exactly one source-preserved, writable, file-backed 8-byte GOT entry owned by
  an `R_AARCH64_TLS_TPREL64` relocation for the same symbol and addend.

The shared layout/materializer is sufficient for this narrow form because it
copies source bytes, emits transformed code only in a planned executable
region, and already reparses/preserves PT_TLS and relocation metadata. The GOT
entry is not rewritten or relocated: its source file/virtual range, bytes,
relocation identity, writable ownership, and output mapping are validated and
must remain unchanged. Missing, duplicate/overlapping, symbol/module/addend
mismatched, or non-writable GOT ownership is rejected before publication.

The other initial-exec forms remain fail-closed in this slice:

```text
R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21
R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC
R_AARCH64_TLSIE_LD_GOTTPREL_PREL19
```

This is ABI/toolchain shape evidence only. Native transformed glibc, musl, and
bionic execution, lifecycle evidence, and the Ubuntu 24.04 runtime matrix are
still outstanding.
