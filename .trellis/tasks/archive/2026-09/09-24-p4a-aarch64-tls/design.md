# P4-A Design: AArch64 TLS Semantics

## Contract

Define a bounded initial-exec TLS model covering module allocation, TLS
relocation, current-thread initialization, and release ordering. Dynamic TLS,
new-thread initialization, reentrancy, and unload while a live thread references
an image are explicit deferred boundaries for this slice.

## Evidence

Use a real AArch64 ET_DYN fixture with an initial-exec TLS value and an entry
status oracle. Static PT_TLS mutations remain negative boundary tests; they are
not a positive support oracle. A future threaded slice must add new-thread and
teardown observations before claiming them.
