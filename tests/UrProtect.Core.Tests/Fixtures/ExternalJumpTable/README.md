# External signed-relative jump-table consumer fixture

These stripped AArch64 shared objects exercise the managed, exact external
provider-table publication slice. The provider exports one read-only four-entry
`R_AARCH64_RELATIVE`-style signed-relative table and four bounded target
functions. The consumer depends on its exact SONAME and has `urp_entry` and
`urp_observer` functions with a four-entry bounds check, `ADRP`/`LDR` through a
unique `R_AARCH64_GLOB_DAT` GOT slot, `LDRSW`, table-base `ADD`, and `BR`.

Rebuild with the repository's AArch64 cross tools:

```sh
cd native/urprotect-runtime
AS=aarch64-linux-gnu-as LD=aarch64-linux-gnu-ld make external-provider-fixtures
mkdir -p ../../tests/UrProtect.Core.Tests/Fixtures/ExternalJumpTable
aarch64-linux-gnu-ld -shared -z separate-code -z max-page-size=0x1000 \
  --build-id=sha1 --hash-style=gnu -soname liburprotect-jump-table-provider.so.1 \
  build/host-context-external-provider-fixture.S.o \
  -o ../../tests/UrProtect.Core.Tests/Fixtures/ExternalJumpTable/liburprotect-jump-table-provider.so.1
aarch64-linux-gnu-ld -shared -z max-page-size=0x1000 \
  --build-id=none --hash-style=gnu --no-undefined -z now \
  build/host-context-external-provider-consumer-fixture.S.o \
  -L../../tests/UrProtect.Core.Tests/Fixtures/ExternalJumpTable \
  -l:liburprotect-jump-table-provider.so.1 \
  -o ../../tests/UrProtect.Core.Tests/Fixtures/ExternalJumpTable/liburprotect-external-table-consumer.so
aarch64-linux-gnu-strip --strip-all ../../tests/UrProtect.Core.Tests/Fixtures/ExternalJumpTable/*.so*
```

The provider file path is supplied only through trusted test/operator input; it is
not serialized into Protected Image semantic snapshots.
