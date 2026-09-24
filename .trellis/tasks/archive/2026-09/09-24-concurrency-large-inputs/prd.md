# Add concurrency and large-input regressions

## Goal

Prove deterministic and bounded behavior when reusable parser/codec/pipeline
operations run concurrently and when inputs approach configured or practical
large-input limits.

## Requirements

- Exercise concurrent parser, validator, frame codec, and no-op pipeline use
  with shared immutable inputs and independent mutable outputs.
- Compare concurrent results to a serial oracle, including diagnostics, model
  shape, encoded bytes, and byte-preserving copies.
- Cover exact-limit and limit-plus-one cases, integer-overflow boundaries, and
  selected multi-megabyte inputs for parser/frame/copy/report paths.
- Use fixed PR worker/iteration/size profiles and amplified nightly profiles;
  record seed, parameters, elapsed time, and resource observations.
- Verify failed filesystem publication leaves no partial output and enforce
  process-level timeouts without inventing undocumented thread-safety claims.

## Ordering and integration notes

The suite may be prototyped independently, but final helpers and diagnostics
should use the contract/assertion conventions from
`09-24-constants-and-assertions`. The end-to-end child consumes this child's
profile names and evidence schema when wiring CI.

## Acceptance Criteria

- [x] PR concurrency tests are deterministic across repeated runs and verify
      the documented stateless/reusable APIs only.
- [x] Boundary and multi-megabyte suites cover success, rejection, overflow,
      and no-partial-publication behavior within explicit budgets.
- [x] Nightly amplification is separate from PR smoke and retains parameters
      and failure artifacts.
- [x] Managed tests and relevant native/CLI tests pass without changing the
      supported product contract.
<!-- End of task artifact. -->
<!-- End of task artifact. -->
