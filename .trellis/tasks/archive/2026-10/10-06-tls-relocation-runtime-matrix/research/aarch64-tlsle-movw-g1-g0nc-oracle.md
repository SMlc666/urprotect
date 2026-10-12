# AArch64 TLSLE MOVW G1/G0_NC ABI and assembler-shape oracle

## Bounded implemented form

This iteration implements only the ordered instruction-relocation pair:

```text
R_AARCH64_TLSLE_MOVW_TPREL_G1      (project value 545 / 0x221)
R_AARCH64_TLSLE_MOVW_TPREL_G0_NC   (project value 548 / 0x224)
```

The values match the host ABI declarations in `/usr/include/elf.h` and LLVM
21's `ELFRelocs/AArch64.def`; the project's `ElfConstants` declares the same
numeric values. The glibc ELF header describes G1 as TP-relative `MOV{N,Z}`
bits 31:16 and G0_NC as `MOVK` bits 15:0 without a range check. The accepted
instruction pair is therefore a 64-bit `MOVZ` or `MOVN` with `hw=1`, immediately
followed by a 64-bit `MOVK` with `hw=0`; both destinations must be the same
general register other than register 31. The paired RELA records must be
consecutive in instruction/address order, have pair ordinals 0 then 1, bind the
same resolved TLS symbol, and carry identical addends.

The access form exercised by the positive oracle is:

```asm
movz x9, #:tprel_g1:tls_value
movk x9, #:tprel_g0_nc:tls_value
mrs  x10, tpidr_el0
add  x9, x10, x9
ldr  w0, [x9]
ret
```

The resolver requires the MRS source register and MOVW result register to feed
one unshifted 64-bit ADD-register address formation, whose destination is the
base register of the immediately following TLS memory access. The MRS must sit
immediately before the pair or immediately after it, and the ADD immediately
follows the later of those definitions. It rejects different MOVW destinations,
wrong move opcode/shift, interleaved pair instructions, mismatched addends, and
registers not connected through TP-relative ADD to the access. Other TLSLE MOVW
forms (G2, G1_NC, G0) and other pair combinations remain unsupported.

## Independent assembler observation

The source above, with `tls_value` defined as an 8-byte `STT_TLS` object in
`.tdata`, was assembled locally with:

```sh
aarch64-linux-gnu-gcc -c -fPIC -o tls_movw.o tls_movw.S
readelf -rW tls_movw.o
aarch64-linux-gnu-objdump -dr tls_movw.o
```

Observed toolchain: GCC 15.2.0; GNU assembler/readelf/objdump 2.46. The actual
`.rela.text` entries were offsets `0x0` and `0x4`, types
`R_AARCH64_TLSLE_MOVW_TPREL_G1` and `R_AARCH64_TLSLE_MOVW_TPREL_G0_NC`, each
naming `tls_value` with addend `0`. The disassembly was:

```text
0: d2a00009  movz x9, #0x0, lsl #16
   R_AARCH64_TLSLE_MOVW_TPREL_G1 tls_value
4: f2800009  movk x9, #0x0
   R_AARCH64_TLSLE_MOVW_TPREL_G0_NC tls_value
8: d53bd04a  mrs x10, tpidr_el0
c: 8b090149  add x9, x10, x9
10: b9400120 ldr w0, [x9]
14: d65f03c0 ret
```

A static no-libc link of the same object with GNU ld (`aarch64-linux-gnu-gcc
-nostdlib -static -Wl,-e,tls_fixture`) consumed both records; the linked image
has no remaining relocations and contains the contiguous resolved instructions
`d2a00009 movz x9, #0, lsl #16` and `f2800209 movk x9, #0x10`, followed by the
same TP-relative MRS/ADD/load chain. Thus the ABI-header values and object
relocation order agree with both the real assembler object and the real linked
instruction shape. The final link is shape evidence only, not transformed-image
runtime evidence.

The test fixture mirrors the linker's source-object shape and retains the
symbol-indexed adjacent RELA records in the repository's synthetic ET_DYN
container. Its positive managed cases exercise `+1`/`MOVZ` and `-1`/`MOVN`
matched relocation addends. They prove typed planning, canonical snapshot
round-trip, shared layout/materialization and output reparse only; this object
fixture is not a transformed runtime oracle.

## Runtime/evidence boundary

This assembler/ABI check does not promote TLS runtime support. Transformed
AArch64 glibc, musl, and bionic execution and lifecycle evidence remain
outstanding, as do the other local-exec MOVW forms and all other TLS models.
