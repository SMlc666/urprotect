# Architecture foundation audit record

## Cross-layer flows

1. **ELF validation/reporting:** input bytes -> `NoOpPipeline` -> bounded
   `ElfParser`/`LoadMap` -> `ElfValidator` and ordered `DiagnosticBag` ->
   `ProductReportFactory` -> CLI human/JSON output and exit-code mapping.
2. **Pack/native dispatch:** source and launcher -> `ElfPackService` /
   `PayloadFrameCodec` -> profile wrapper/trailer -> native frame runtime ->
   HostContext callbacks -> image preflight -> sealed memfd/loader -> exact
   symbol dispatch -> release -> status/evidence.
3. **Public sample evidence:** locked registry -> acquisition/hash/path checks
   -> bounded fingerprint/readelf -> isolated oracle -> normalized evidence ->
   result vocabulary/aggregate coverage -> post-run evidence gate.
4. **Change-to-release:** source/tests/fixtures -> managed/native/Python/
   fuzz/stress gates -> CI artifacts -> manifest/evidence checks -> release and
   provenance package.

## Contract owners and findings

| Contract | Owner | Finding / containment |
|---|---|---|
| ELF bytes and address mapping | `BoundedReader`, typed address values, `LoadMap`, `ElfParser` | Parser remains a later extraction target; consumers must not reparse bytes or duplicate address arithmetic. |
| Current frame ABI | managed `PayloadFrameCodec` plus native frame header/probe | Keep existing per-language owners and drift tests until a simpler canonical source is proven. |
| HostContext image preflight | `native/urprotect-runtime/host_image_validation.c` | Extracted in this child; runs before image handle creation. |
| HostContext resource/lifetime | `native/urprotect-runtime/host_adapter.c` | Owns memfd, seals, loader handoff, symbol lookup, release, and descriptor cleanup; no duplicate byte validation. |
| CLI/report/exit contract | `CliApplication`, `ProductReportFactory`, golden/CLI tests | Large mixed-responsibility hotspot deferred to CLI/release child. |
| Sample result/evidence vocabulary | real-sample manifest and validator scripts | Repeated script semantics remain a later evidence-tooling child concern. |

## Refactor record

The first extraction moved the bounded native image preflight from
`host_adapter.c` into `host_image_validation.c/.h`, wired all runtime and
symbol-self-test link paths, and added direct positive/null/truncated
characterization assertions. No support status, frame layout, ABI, CLI exit,
or release claim changed. The rollback point is to restore the validation
block in `host_adapter.c`, remove the new object/header, and revert the direct
preflight assertions.

## Remaining hotspots

- `ElfParser.cs`: mixed table parsing, metadata extraction, and orchestration;
  next child extracts one cohesive table/feature owner at a time.
- `PayloadFrame.cs`: layout, version/profile validation, encode/decode,
  decompression, wrapper discovery, and trailer handling; retain one codec.
- `CliApplication.cs`: options, orchestration, output, and Linux handoff;
  preserve one JSON stream and stable exit codes during later extraction.
- `host_context_self_test.c`: test-only fixture mutations and assertions;
  future feature children should extend test helpers without moving them into
  production preflight.
- Evidence scripts: repeated schema/hash/path checks; consolidate only after
  preserving the current manifest vocabulary and evidence gates.
