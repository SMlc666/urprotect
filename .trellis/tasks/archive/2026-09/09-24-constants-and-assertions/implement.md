# Constants and assertion implementation plan

1. Inventory and classify literals with repository searches and record owners
   in `tests/ContractInventory.md`.
2. Consolidate managed and native duplicate contract values through
   `ElfHeaderOffsets`, `ElfProgramHeaderOffsets`, `PayloadFrameCodec` layout
   constants, and `native/urprotect-runtime/include/urp/payload_frame.h`.
3. Add `native/urprotect-runtime/contract_probe.c` and
   `ContractLayoutTests.cs` for the cross-language drift check.
4. Add focused xUnit helpers in `TestAssertions.cs` and migrate repeated
   diagnostic/result/byte-identity patterns in the high-value suites.
5. Run managed tests, Python matrix tests, native self-tests, and inspect the
   diff for accidental wire-value changes.

Validation:

```sh
dotnet test tests/UrProtect.Core.Tests/UrProtect.Core.Tests.csproj --configuration Release
python3 tests/test_fixture_matrix.py
python3 tests/test_regression_matrix.py
make -C native/urprotect-runtime contract-check
make -C native/urprotect-runtime test
```
<!-- End of task artifact. -->
