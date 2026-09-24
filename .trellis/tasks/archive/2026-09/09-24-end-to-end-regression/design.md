# End-to-end regression design

Reuse the current CLI tests and native scripts as execution authorities. Add
only missing observable scenarios and a separate machine-readable regression
matrix containing command, tier, platform requirement, budget, expected result,
and artifact witness. Keep compatibility manifest semantics unchanged.

PR rows are deterministic managed/native smoke cases. Nightly adds full fuzz,
stress, fixture, and platform rows. Release repeats packaging and compatibility
evidence. Optional Android remains an explicit unavailable result when its
prerequisites are absent.
<!-- End of task artifact. -->
