# AArch64 TLSIE ADRP/LD64 ABI and GNU oracle

## Bounded implemented form

This slice accepts only the ordered instruction/relocation pair:

```text
R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21       (541 / 0x21d)
R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC     (542 / 0x21e)
```

`/usr/include/elf.h` declares 541 as page-relative ADRP bits 32:12 and 542 as direct LD64 offset bits 11:3. LLVM 21 `/usr/include/llvm-21/llvm/BinaryFormat/ELFRelocs/AArch64.def` declares the same values (`0x21d`, `0x21e`). `R_AARCH64_TLS_TPREL64` is 1030 (`0x406`) in both project and system declarations and remains the loader-owned GOT relocation.

The managed form requires:

```asm
adrp xN, :gottprel:tls_value
ldr  xN, [xN, :gottprel_lo12:tls_value]
mrs  xM, tpidr_el0
add  xN, xM, xN
ldr/str Wt, [xN]
ret
```

The two instruction relocations are consecutive in virtual/file address order, pair ordinals 0 and 1, bind the same defined `STT_TLS` symbol and addend, and use the same GOT entry. The source relocatable LD64 low-12 field is zero; output materialization computes the scaled low-12 field from the preserved GOT slot address. ADRP page congruence and signed 21-bit page range are checked against the output instruction address. The LD64 instruction must be 64-bit unsigned-immediate, use the ADRP destination as base, use a nonzero general-register result, and retain scale eight. The TP-relative ADD and final scalar TLS access must remain connected to that result.

## Independent GNU observation

Fixture source:

```asm
.text
.global tls_fixture
tls_fixture:
    adrp x9, :gottprel:tls_value
    ldr x9, [x9, :gottprel_lo12:tls_value]
    mrs x10, tpidr_el0
    add x9, x10, x9
    ldr w0, [x9]
    ret
.section .tdata,"awT",%progbits
.align 3
tls_value:
    .xword 0x1122334455667788
```

Commands run on native AArch64 toolchain:

```sh
aarch64-linux-gnu-gcc -c -fPIC -o /tmp/urprotect-tlsie.o /tmp/urprotect-tlsie.S
readelf -rW /tmp/urprotect-tlsie.o
objdump -dr /tmp/urprotect-tlsie.o
aarch64-linux-gnu-gcc -nostdlib -shared -fPIC -Wl,-e,tls_fixture \
  -o /tmp/urprotect-tlsie.so /tmp/urprotect-tlsie.o
readelf -hW -lW -SW -rW -sW /tmp/urprotect-tlsie.so
objdump -dr /tmp/urprotect-tlsie.so
```

Observed toolchain: GCC 15.2.0, GNU assembler/readelf/objdump 2.46. The relocatable object contains exactly:

```text
0x0  R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21    tls_value + 0
0x4  R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC  tls_value + 0
```

and disassembles as `90000009 adrp x9`, `f9400129 ldr x9, [x9]`, followed by the TP-relative chain. The linked shared object contains one writable `.got` owner at virtual address `0x1ffe0`:

```text
0x1ffe0  R_AARCH64_TLS_TPREL64  tls_value + 0
```

The linked code resolves to `adrp x9, 0x1f000` and `ldr x9, [x9, #4064]`; `4064 == 0x1fe0` is the page-relative GOT low-12 displacement. PT_TLS remains initialized template plus loader-owned per-thread allocation/zero-fill. This is ABI/linker shape evidence only, not transformed glibc, musl, bionic, or lifecycle runtime evidence.

## Rejection boundary

Wrong page relocation, wrong LD64 width/scale/offset/register, non-adjacent or reversed pair, interleaving, symbol/module/addend mismatch, missing/overlapping/non-writable GOT ownership, source/snapshot mismatch, address-map conflict, and output page/low-12 mismatch fail before artifact publication. Generic direct-call and unrelated PC-relative instructions remain rejected.
