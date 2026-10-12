# AArch64 TLSIE LD_GOTTPREL_PREL19 GNU oracle

## Exact toolchain shape

The pinned local AArch64 GNU toolchain is GCC 15.2.0 with GNU assembler/readelf/objdump 2.46. This source assembles successfully:

```asm
.text
.global tls_fixture
tls_fixture:
    ldr x9, :gottprel:tls_value
    mrs x10, tpidr_el0
    add x9, x10, x9
    ldr w0, [x9]
    ret
.section .tdata,"awT",%progbits
.align 3
tls_value:
    .xword 0x1122334455667788
```

The relocatable object contains one standalone `.rela.text` record:

```text
0x0  R_AARCH64_TLSIE_LD_GOTTPREL_PREL19  tls_value + 0
```

The instruction is `0x58000009`, a 64-bit `LDR X9` literal load. The following instructions are `MRS X10, TPIDR_EL0`, `ADD X9, X10, X9`, `LDR W0, [X9]`, and `RET`. There is no preceding ADR/ADRP and no paired instruction relocation.

A GNU shared link retains one writable GOT owner:

```text
0x1ffe0  R_AARCH64_TLS_TPREL64  tls_value + 0
```

The linked literal load is `ldr x9, 1ffe0`, so the relocation target is the GOT slot itself. The GOT slot remains loader-owned and thread-pointer-relative; PT_TLS retains the initialized template and loader zero-fill.

## ABI semantics and bounded recognizer

`R_AARCH64_TLSIE_LD_GOTTPREL_PREL19` is ABI value `543` (`0x21f`). It writes the AArch64 literal-load `imm19` field (bits 20:2), with a signed 19-bit displacement scaled by four bytes. The target is `GOT address + RELA addend`, and the place is the output instruction address. The source relocatable encoding has an immediate of zero; output materialization recomputes the signed, four-byte-scaled displacement against the preserved GOT owner.

The managed slice accepts only a 64-bit `LDR Xt` literal form, a nonzero general destination register, exactly one immediately following TP read, unshifted register `ADD` consuming the TP value and loaded GOT value, and one immediately following scalar TLS memory access using the ADD destination as its base. It rejects 32-bit or other literal widths, register/resource mismatches, signed-range or alignment failures, missing/duplicate/overlapping/non-writable GOT ownership, identity/addend mismatches, and source/output mapping conflicts. Generic direct calls and unrelated PC-relative instructions retain their existing rejection behavior.

This is semantic/layout evidence only. No native glibc, musl, bionic, lifecycle, or runtime-support claim is made by this oracle or fixture.
