# AArch64 symbol-version definition fixture

`liburp-versioned.so` is a deterministic, compiler/linker-produced AArch64
ELF64 shared object used only as parser input. It is not executed by tests.
The source and GNU ld version script are retained alongside the binary.

Build with an AArch64 Linux GCC/binutils toolchain. The fixture uses the SysV
hash table so its symbol count is explicit in the dynamic metadata; this keeps
the version-index vector tied to the exact `.dynsym` count without relying on
GNU-hash chain inference.

```sh
aarch64-linux-gnu-gcc -shared -fPIC -nostdlib \
  -Wl,-z,max-page-size=4096 \
  -Wl,--hash-style=sysv \
  -Wl,--version-script=versions.map \
  -Wl,-soname,liburp-versioned.so \
  -o liburp-versioned.so versioned.c
```

The fixture contains `DT_VERDEF`/`DT_VERDEFNUM` with the base definition
`liburp-versioned.so`, definitions `URP_1.0` and `URP_2.0`, and `URP_1.0` as
the parent auxiliary of `URP_2.0`. The checked-in fixture path is
`tests/UrProtect.Core.Tests/Fixtures/SymbolVersions/liburp-versioned.so`; its
SHA-256 is
`4fb8ffa362ce8a18590eff735c971aaf217eb4dcd338bf071810fe0b3c971ae8`. Compiler
build IDs may vary by toolchain revision, so this hash
pins the exact repository artifact rather than every independently rebuilt copy.
