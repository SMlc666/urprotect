# Benchmark

AsmStone includes a dependency-free .NET 8 benchmark harness for measuring
the binary decoder, encoder, generated catalog, and byte-oriented API without
requiring a package restore.

Run a release build and benchmark pass with:

```sh
dotnet build AsmStone.sln --configuration Release --nologo
dotnet run --project tools/AsmStone.Benchmark/AsmStone.Benchmark.csproj \
  --configuration Release --no-build -- --operations=250000 --warmup=25000 --samples=5
```

The output reports median nanoseconds per operation, throughput, and bytes
allocated per operation. Raw decode cases measure the zero-allocation generated
core; full decode cases include semantic IR construction. The checksum column
prevents the measured calls from being optimized away. Results are machine- and
runtime-dependent; use the same Release command and options when comparing
changes.

The default cases cover generated raw and semantic decoding, catalog lookup and
field decoding, generated encoding, raw TableGen field encoding, and the
byte-span overloads.

The object API keeps its public `A64Instruction` representation. The generated
numeric field and binding plan is cached at catalog initialization, so encoding
does not parse metadata strings on the hot path.

For a zero-allocation semantic decode, the caller owns the operand storage:

```csharp
var operands = new A64OperandView[8]; // allocate once and reuse
if (AsmStoneApi.TryDecodeView(word, address, features, operands, out var instruction, out var diagnostic))
{
    var mnemonic = instruction.Mnemonic;
}
```
