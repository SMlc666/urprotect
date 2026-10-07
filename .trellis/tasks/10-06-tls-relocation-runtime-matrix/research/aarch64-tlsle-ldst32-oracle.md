# AArch64 TLSLE LDST32 ABI/toolchain oracle

## Implemented bounded pair

This slice accepts only the ordered pair:

```text
R_AARCH64_TLSLE_ADD_TPREL_HI12       (549 / 0x225)
R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC (557 / 0x22d)
```

The ABI declarations in `/usr/include/elf.h` describe `ADD_TPREL_HI12` as the
TP-relative ADD immediate bits 23:12 and `LDST32_TPREL_LO12_NC` as the 32-bit
load/store offset bits 11:2 without a range check. The accepted instruction
shape is therefore `ADD (64-bit, immediate, LSL #12)` followed immediately by
an unsigned-immediate 32-bit `LDR Wt` or `STR Wt`, with the ADD destination equal
to the load/store base. The load/store immediate is scaled by four and must be
encoded in the low-12 field; no LDST8/16/64/128 form is accepted here.

## GNU assembler/linker observation

A local fixture was assembled with GCC/binutils AArch64 tools:

```sh
aarch64-linux-gnu-gcc -c -fPIC -o tls_ldst32.o tls_ldst32.S
readelf -rW tls_ldst32.o
aarch64-linux-gnu-objdump -dr tls_ldst32.o
aarch64-linux-gnu-gcc -nostdlib -static -Wl,-e,tls_fixture \
  -o tls_ldst32.elf tls_ldst32.o
readelf -rW tls_ldst32.elf
aarch64-linux-gnu-objdump -d tls_ldst32.elf
```

Observed toolchain: GCC 15.2.0 and GNU assembler/readelf/objdump 2.46. The
relocatable `.rela.text` records were contiguous and in instruction order:

```text
Offset  Type                                      Addend
0x4     R_AARCH64_TLSLE_ADD_TPREL_HI12           0
0x8     R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC     0
```

The corresponding disassembly was:

```text
0: d53bd04a  mrs  x10, tpidr_el0
4: 91400149  add  x9, x10, #0, lsl #12
8: b9400120  ldr  w0, [x9]
c: d65f03c0  ret
```

The static GNU link consumed both records. The linked instruction sequence
retained the adjacent ADD and 32-bit load and resolved the low field to the
scale-four offset for the TLS symbol. This is ABI/linker shape evidence only;
it is not transformed-image runtime evidence.

## Recognition boundary

The managed recognizer additionally requires one TPIDR_EL0 MRS immediately
before the ADD, a connected 64-bit ADD register address formation, and exactly
one following 32-bit unsigned-immediate load/store. It verifies relocation
order, pair ordinals, same symbol identity, equal addends, exact instruction
width/opcode, base/destination register ownership, and contiguous source ranges.
The pair remains fail-closed for LDST8/16/64/128, unscaled or other opcodes,
wrong register wiring, gaps/interleaving, order/addend mismatch, and source or
snapshot identity mismatch. Runtime support claims remain open.
