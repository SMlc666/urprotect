# Concurrency and large-input design

Use immutable shared fixture bytes, independent output buffers/directories, and
fixed worker/iteration profiles. A serial invocation is the oracle; concurrent
results compare diagnostics, model shape, encoded bytes, and copy identity.

Use custom small limits for exact/plus-one tests and selected multi-megabyte
inputs rather than allocating the production maximum in every test. Separate
PR and nightly profiles, enforce process timeout, and retain parameters and
failure artifacts. No undocumented thread-safety guarantee is added.
<!-- End of task artifact. -->
