# Dynamic-import indirect-call fixture

`liburp-glob-dat-indirect.so` is built from
`native/urprotect-runtime/host_context_dynamic_import_fixture.S` by the
`dynamic-import-fixture` Make target. The fixture is a bounded AArch64 shared
object with an undefined global `getpid` `STT_NOTYPE` dynsym row, one non-PLT
`R_AARCH64_GLOB_DAT` GOT owner, and an `ADRP`/page-alias/independent-clobber/
`LDR`/`BLR` sequence. The clobber deliberately overwrites the original ADRP
register after its page value has been copied, exercising reaching-definition
validation rather than just a listed-producer check.
It has no GNU symbol-version table or version-need records, so versioned import
acceptance is not inferred from this fixture.

Rebuild on AArch64 with:

```sh
make -C native/urprotect-runtime dynamic-import-fixture
```

For a cross-build, pass the matching AArch64 assembler and linker as `AS` and
`LD`. The checked-in bytes are consumed by the managed producer/snapshot/
Protected Image/rehydration integration test; native runtime compatibility is
not promoted by that managed test.
