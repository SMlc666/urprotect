# AsmStone

AsmStone is a managed C# AArch64 instruction encoder and decoder library.

The project is being built around a generated, data-driven instruction
description so the implementation can grow to the complete current A64
instruction set without maintaining separate manual assembler and disassembler
opcode tables.

## Current status

The current runtime has a complete generated instruction metadata catalog and
feature-aware decoding. All instruction matching and encoding use the generated
TableGen catalog; there is no separate opcode-specific implementation path.
Generated decoding materializes common registers, modified registers, immediates,
PC-relative targets, vector lists, system registers, and memory addressing
into the IR; logical/vector immediate codecs preserve semantic values and raw
encodings; text parsing and pretty-printing are
intentionally outside the project boundary.

## Build and test

The repository targets .NET 8. If the SDK is installed outside `PATH`, set
`DOTNET_ROOT` or invoke its absolute path.

```sh
dotnet build AsmStone.sln
dotnet run --project tests/AsmStone.Tests/AsmStone.Tests.csproj
```

The generated binary catalog can be rebuilt from a pinned LLVM checkout with
`scripts/generate-runtime-catalog.sh`. The checked-in catalog is the runtime
default; the external LLVM checkout is only a generation dependency.

The default `AsmStoneApi.TryDecode` uses the complete generated catalog. Use
its feature-aware overload for a target-specific profile. Generated IR has a stable
`SourceName`; passing it to `AsmStoneApi.TryEncode` uses the same generated
field mapping in reverse.
The byte-oriented overloads use little-endian A64 words and accept the same
feature profiles.
The feature enum includes common extension groups such as NEON, SVE/SVE2, SME,
LSE, MTE, pointer authentication, MOPS, FP16, BF16, I8MM, FP8, and CRC;
exact LLVM predicates remain
available through `A64FeatureSet.FromPredicates`.
Strict decode reports `UnsupportedFeature` for a known instruction outside the
selected profile and `UnknownEncoding` only when no generated record matches.
Use `A64FeatureSet.From(features, A64ExecutionMode.Streaming)` when SME/SVE
legality depends on streaming mode.

For a newly added or highly specialized instruction, use
`AsmStoneApi.TryEncodeFields` with the generated TableGen field names. This
provides a complete binary assembly path without introducing a text syntax
layer.
The test suite exercises every complete generated record at its base encoding
and additional randomized variable-bit encodings.
Generated IR also carries control-flow and memory-effect flags sourced from
the pinned TableGen records.
Atomic/exclusive classes expose `IsAtomic` in addition to their load/store and
side-effect flags.
`A64InstructionCatalog` also exposes the pinned LLVM commit and TableGen input
hash used to build the runtime catalog.
`ModifiedRegisterOperand.TryCreate` provides semantic construction for common
shifted and extended register operands.
`AsmStoneApi.TryDecodeRaw` returns a zero-allocation generated instruction view
with raw fields, and `AsmStoneApi.TryDecodeView` writes a zero-allocation
semantic operand view into caller-provided storage. These views share the same
generated matcher and metadata plan as the object-based API.
The object API exposes `GetOperandSemantics()` with generated operand direction,
tie relationships, register constraints, element widths, immediate domains, and
compiled field metadata. Specialized SVE optional-shift immediates, exact FP
immediates, standalone arithmetic modifiers, and SME spill/fill tile-slice
aliases retain their semantic values and raw encodings through round trips.
The span view exposes the same operand kind, direction, modifier, predicate,
lane, memory, register-constraint, field-width, scaling, and semantic-domain
metadata without allocating.
Object encoding also uses the compiled generated operand plan directly; there is
no separate handwritten opcode or operand-dispatch path.
The test suite also reconstructs every generated encoding through the raw field
API, which keeps newly introduced instruction families usable immediately.

## Design direction

- Keep the public intermediate representation stable.
- Generate instruction metadata and codecs from one source of truth.
- Preserve unknown 32-bit words instead of guessing an instruction.
- Use the GNU/LLVM toolchains as binary differential-test oracles.
- Add architecture features explicitly instead of silently accepting an
  instruction that the selected feature set does not enable.

See `docs/ROADMAP.md` and `docs/PROGRESS.md` for the active delivery plan.

The GitLab pipeline includes a pinned LLVM MC oracle and one
`saas-linux-2xlarge-amd64` exhaustive job with 32 embarrassingly parallel
workers. See `docs/EXHAUSTIVE-VALIDATION.md` for the shard contract and local
smoke command.

## License

AsmStone is released under the MIT License. See `LICENSE`.
