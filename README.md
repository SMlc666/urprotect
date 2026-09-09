# urprotect

`urprotect` is a C#/.NET infrastructure foundation for conservative ELF64
AArch64 analysis. The current MVP is intentionally read-only: it validates
supported `ET_DYN` PIE executables and dynamically linked shared objects,
reports bounded ELF metadata, and can emit a byte-identical copy.

It does not yet implement binary protection transformations, relocation
rewriting, runtime injection, code encryption, or control-flow virtualization.

## Build

The project targets .NET 8 and keeps AArch64 decoding behind a project-owned
AsmStone adapter. The pinned AsmStone implementation is integrated separately
from the ELF model so the parser does not depend on a general-purpose ELF
library.

The vendored AsmStone revision and its attribution files are under
`third_party/AsmStone`. The project uses AsmStone only through the adapter and
does not duplicate its generated AArch64 instruction catalog.

```sh
dotnet restore
dotnet build --configuration Release
dotnet test --configuration Release
```

## CLI

```sh
dotnet run --project src/UrProtect.Cli -- validate ./program --copy ./program.checked
```

The copy path is published only after the output bytes have been compared with
the input. Unknown or unsupported data is never rebuilt by the no-op pipeline.
