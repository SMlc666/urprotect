# Exhaustive Validation

AsmStone's full-space differential test checks every 32-bit AArch64 word in
the half-open range `[0, 2^32)`. The GitLab pipeline runs one
`saas-linux-2xlarge-amd64` job and starts 32 independent workers on that
machine. The job supplies each worker with `CI_NODE_INDEX` and
`CI_NODE_TOTAL`; the harness maps each one to a disjoint range with integer
arithmetic, so the workers cover the space exactly once, including
`0xFFFFFFFF`.

## Oracle

The exhaustive job builds LLVM MC from the pinned source commit in
`spec/source-lock.json`, then builds `tools/AsmStone.LlvmOracle`. Each worker
uses LLVM's AArch64 `MCDisassembler` and `MCCodeEmitter` with `+all` target
features. It emits a compact binary result stream rather than one process per
word or a text file per instruction.

The GitLab job caches the configured LLVM build trees using a key derived from
`spec/source-lock.json`. The source checkout is still refreshed and verified on
each run, while unchanged LLVM object files and the oracle link output are
reused. Cold builds use 32 CMake/Ninja build workers on the 2xlarge runner.

Each chunk contains:

- start word, word count, LLVM `Success` count, and `SoftFail` count;
- a SHA-256 semantic fingerprint for each LLVM-success word;
- a bit mask identifying LLVM soft-fail words.

The fingerprint records decode validity, the LLVM opcode identity, selected
control-flow semantics, and the LLVM-canonical re-encoded word.

AsmStone materializes compiled instruction plans lazily during the run. The
instruction source table remains indexed and resident, while predicate, memory,
binding, field, and compiled plans are created only for candidate instructions
that the decoder examines.
The compact decoder bucket uses an 8-bit key and 16-bit candidate indices; the
full mask/value check remains authoritative after bucket selection.

## AsmStone side

Each worker runs the same chunks through the generated catalog and typed
decoder, then requires all of the following:

- LLVM-success words decode through AsmStone with the same generated identity;
- typed operands re-encode losslessly to the original word;
- canonicalized fixed/field bits match LLVM's emitted word;
- control-flow semantic flags match the LLVM descriptor;
- LLVM soft-fail words are counted and excluded from the success fingerprint.

The normal generated round-trip tests remain separate and continue to enforce
lossless preservation of opaque bits. This distinction lets the exhaustive
oracle compare architectural semantics while retaining the library's stronger
binary round-trip contract.

For bounded failure investigation, pass `--diagnose` to
`AsmStone.Exhaustive`. The matching oracle dump reports the first word whose
validity or canonical opcode name differs, for example:

```sh
dotnet run --project tests/AsmStone.Exhaustive/AsmStone.Exhaustive.csproj \
  --configuration Release -- --oracle=PATH \
  --start=0x04200000 --count=0x100000 --diagnose
```

## Local smoke run

After building the pinned LLVM oracle, run a bounded shard with:

```sh
dotnet run --project tests/AsmStone.Exhaustive/AsmStone.Exhaustive.csproj \
  --configuration Release -- \
  --oracle=build/llvm-oracle/asmstone-llvm-oracle \
  --start=0x14000000 --count=0x100000 --chunk-size=0x10000
```

Omitting `--start` and `--count` uses `CI_NODE_INDEX`/`CI_NODE_TOTAL`, or a
single shard when those variables are absent.
