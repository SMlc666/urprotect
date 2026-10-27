# Logging Guidelines

## Current Logging Model

The product has no logging framework and no long-lived service process. Core
libraries return structured diagnostics; they do not write to the console. The
CLI and native launcher are the only runtime boundaries that write process
output.

Use `DiagnosticSeverity`, `DiagnosticCode`, `Diagnostic`, and `DiagnosticBag`
from `src/UrProtect.Core/Diagnostics/Diagnostic.cs` for parser and packer
events. A diagnostic may include an ELF file offset so callers can present a
stable machine-readable failure without parsing a log line.

## Output Rules

- Human-readable success output and JSON stream reports go to stdout.
- Errors go to stderr unless `--json -` is selected; JSON stream mode reserves
  stdout for exactly one report document.
- `CliApplication.Run` maps diagnostics to stable `ProductExitCode` values. Do
  not add ad-hoc process exits based on message text.
- `CliApplication.TryRunEmbeddedPayload` writes native handoff failures to
  stderr and preserves the original environment and payload process streams.
- The native launcher emits a short diagnostic class and message to stderr; it
  does not dump payload bytes or environment contents.

## Severity Mapping

There is no `Debug` or `Information` log sink. The available diagnostic levels
have these meanings:

- `Info`: non-failing metadata that may be included in a report.
- `Warning`: input metadata is preserved or analysis is incomplete, but the
  requested validation remains usable; unknown AArch64 instruction or
  relocation classification is an example.
- `Error`: the parser, packer, publication step, or runtime handoff cannot
  satisfy its contract. Errors make a result unsuccessful.

## Failure Evidence

CI scripts retain logs, environment manifests, frame metadata, wrappers, and
toolchain provenance as artifacts. Use those scripts for build/runtime evidence
instead of adding verbose logging to production parser code:

- `.github/scripts/record-environment.sh` records host and toolchain facts.
- `scripts/run-packed-fixture-matrix.sh` records baseline/wrapper output and
  status comparisons.
- `native/urprotect-launcher/test_launcher.sh` records malformed-frame cases.

Unexpected top-level CLI exceptions may include a generated correlation id in
the `InternalFailure` message. This is the only request-like correlation
mechanism in the current product.

## Do Not Emit

Never write source paths, temporary directory names, complete ELF bytes, raw
payload data, environment arrays, or secrets into normal reports or diagnostic
messages. Keep stdout stable for scripts and JSON consumers. Do not use
`Console.Write*` in `UrProtect.Core`; inject `TextWriter` only at the CLI
boundary when output needs testing.
