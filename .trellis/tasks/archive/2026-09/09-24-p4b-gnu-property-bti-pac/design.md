# P4-B Design: GNU Property, BTI, and PAC Semantics

## Contract

Define a bounded AArch64 GNU property-note subset and the host negotiation,
instruction-state, BTI/PAC, and memory-protection obligations for that subset.
Keep parser recognition, outer-wrapper execution, and HostContext acceptance as
separate claims.

## Evidence

Use property-bearing AArch64 fixtures plus host-state observations. Conflicting,
malformed, and unspecified properties must fail before invalid dispatch and
leave the image handle clean.
